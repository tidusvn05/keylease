# KeyLease desktop

This is the thin presentation client for the versioned local IPC API. One
Flutter code base targets macOS, Windows, Android and iOS; macOS is the first
deployment and acceptance target. The UI is built on
[Forui](https://forui.dev) `0.26.0`, pinned exactly, with Flutter 3.47.2. It
provides vault/group navigation, metadata search, login create/edit/delete,
connection posture, exact-request approval decisions and the redacted audit
view. It does not contain crypto, KDBX parsing, policy decisions, or connector
code.

Every non-status screen authenticates with a registered client and is checked
against the same policy engine as the CLI. A typical desktop client needs
explicit grants for the entry/group operations it uses, including separate
`entry:read_username` and exceptional `entry:read_secret` grants for copy,
password reveal, and TOTP, plus `connection:list`,
`connection:add`, `connection:enroll`, `connection:unenroll`,
`connection:test`, `connection:refresh`, `connection:disconnect`,
`connection:revoke`, `group:update`, `group:delete`, `approval:list`,
`approval:decide`, and `audit:query`. The UI rejects symlinked,
oversized, or group/world-readable client-token files and bounds IPC requests
and responses to 4 MiB.

## Layout

```text
lib/
├── main.dart                  # runApp only
├── app/                       # KeyLeaseApp, theme, adaptive shell, shortcuts
├── core/
│   ├── rpc/                   # line-delimited JSON client + typed errors
│   ├── models/                # typed views over the IPC payloads
│   ├── state/                 # AppController, VaultController, drafts
│   └── platform/              # native adapter interfaces
├── features/                  # onboarding, vault, connections, approvals,
│                              # activity, settings
└── ui/
    ├── tokens/                # KeyLease design tokens
    └── components/            # EntryRow, SecretField, RequestSummary, …
```

The shell adapts to the window: a persistent sidebar with a resizable
list/detail split on desktop, a rail on tablets, and compact navigation with a
list → detail route on phones. State, validation, permission semantics and the
RPC contract are shared; only the shell changes.

## Build and run

The macOS runner is checked in. Build and run it on a macOS Flutter workstation
with Flutter 3.47.2:

```sh
flutter pub get
flutter analyze
flutter test
flutter run -d macos
```

The app has no native plugin dependencies, so
`flutter config --enable-swift-package-manager` is not required.

Start `keylease serve --start-locked` first. In Settings, select the mode-0600
client-token file issued by `keylease client register`, then unlock from the
toolbar. The native open panel holds security-scoped access to that token for
the app session. System sleep and screen-lock notifications ask the authenticated
client to lock the daemon. The desktop transport normally receives only
metadata, redacted audit records, approval digests, and scoped operation
results. A reveal/copy/TOTP request returns only the requested field after an
exact-resource capability check and adds a value-free audit record. The native
macOS adapter writes sensitive values to the clipboard, clears them after 30
seconds only if the user has not replaced the clipboard, and also clears them
on sleep, screen lock, or manual vault lock.

Google Workspace setup opens Google's desktop OAuth/Picker flow in the system
browser. The native runner only opens an HTTPS URL whose host is exactly
`accounts.google.com`; the Rust service owns the loopback callback, state, PKCE,
code exchange, selected-file validation, and encrypted token storage. OAuth
tokens never enter Flutter method arguments or state.

The native menu bar is wired in `macos/Runner/MainFlutterWindow.swift`: macOS
consumes a menu key equivalent before the Flutter view sees it, so the
template's `Find… ⌘F` and `Preferences… ⌘,` items are retargeted onto the app's
own intents, and a Vault menu adds New Item ⌘N, Refresh ⌘R and Lock Vault ⌘L.
The window restores its last size and position.

Signing/notarization and exercising the sandbox, security-scoped URL, VoiceOver
and sleep/screen-lock behavior remain macOS release acceptance checks. See
[docs/macos-ui-ux-improvement-plan.md](../../docs/macos-ui-ux-improvement-plan.md)
for the acceptance checklist and what is still unverified.
