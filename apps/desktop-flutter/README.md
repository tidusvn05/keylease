# KeyLease desktop

This is the thin macOS presentation client for the versioned local IPC API. It
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

The macOS runner is checked in. Build and run it on a macOS Flutter workstation:

```sh
flutter run -d macos
```

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

Signing/notarization and exercising the sandbox, security-scoped URL, and
sleep/screen-lock behavior remain macOS release acceptance checks.
