# KeyLease desktop (native SwiftUI app)

The macOS app target — a separate SwiftPM package so that
[`../desktop-macos`](../desktop-macos) (`KeyLeaseCore`) keeps building and
testing on Linux. Everything here requires macOS 14+ and Xcode ≥16.

## Run in development

```sh
# helper resolution: $KEYLEASE_HELPER → bundled Resources → ~/.local/bin
export KEYLEASE_HELPER="$(pwd)/../../target/debug/keylease"
swift run        # spawns `keylease desktop serve` detached if no daemon is up
```

## Build a .app

```sh
../../scripts/package-macos-swift.sh            # Release universal2 → ../../build/macos-swift/KeyLease.app
../../scripts/package-macos-swift.sh --install  # also replace /Applications/KeyLease.app
../../scripts/package-macos-swift.sh --dmg      # also ../../build/macos-swift/KeyLease-<version>.dmg
```

The bundle's version comes from the workspace `Cargo.toml`, not from
`Info.plist` (see [releasing](../../docs/releasing.md#the-macos-app)).

The script embeds the `keylease` helper and the LaunchAgent plist via
`../scripts/prepare-macos-runtime.sh`, then signs the bundle
(`EXPANDED_CODE_SIGN_IDENTITY` overrides the default ad-hoc signature).

## Layout

```text
Sources/KeyLease/
├── KeyLeaseApp.swift       # @main, WindowGroup + Settings scene, Vault menu
├── AppController.swift     # phase machine (port of the Dart AppController)
├── VaultController.swift   # search/view/reveal/totp over KeyLeaseCore
├── RuntimeService.swift    # keylease CLI + SMAppService (port of the bridge)
├── SecurityService.swift   # pasteboard clear, lock signals, URL allowlist
├── ConnectionDefaults.swift
└── Views/                  # phase router, unlock, onboarding, vault UI
```

The port has not yet been built and tested on a Mac in this branch; build it
with `swift build && swift test` before relying on it.
