# leasegate_vault_ui

Everything above the transport: the typed views over the IPC payloads, the
session and feature state, the design tokens and the whole feature UI.

Consumed by `apps/mobile-flutter`, which supplies its own composition root and
the platform code: the in-process FFI client and app-private storage.

## Rules

- **No `dart:io`, and no plugins.** Both would tie this package to a platform.
  Anything needing either belongs behind `SecurityAdapter`,
  `LocalRuntimeAdapter`, `PreferencesStore` or `KeyLeaseClient`, which the host
  implements.
- **Differences between clients are values, not forks.** `AppCapabilities`
  decides what a build offers; both apps compile the identical widget tree.
  Defaults are all `false` so a new capability cannot silently appear somewhere
  it does not belong.
- **The RPC contract is not defined here.** `crates/keylease-rpc` owns it, and
  `test-vectors/rpc/commands.json` freezes the command names — renaming one
  breaks this package with no compile error anywhere in the Rust tree.

## Testing

`lib/testing.dart` holds the fakes both apps test against. It is under `lib/`
rather than `test/` because a package's test directory is not importable by
consumers and its dev dependencies are not transitive.

```sh
flutter analyze && flutter test
```

The suite covers both form factors: `test/compact_layout_test.dart` and
`test/capabilities_test.dart` drive the shell at 412×915 as an Android phone,
alongside the desktop sizes.
