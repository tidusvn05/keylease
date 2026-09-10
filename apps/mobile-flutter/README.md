# Leasegate Vault (Android)

The Android vault client. The user interface, state and RPC contract all come
from [`packages/leasegate_vault_ui`](../../packages/leasegate_vault_ui); this app
supplies only what differs per platform.

## How it differs from the desktop client

The desktop reaches the vault over a Unix socket to a `keylease serve` daemon.
Android cannot host that daemon, so the Rust core runs **inside the app process**
behind a C ABI (`crates/keylease-mobile`), called from a worker isolate.

That removes the process boundary the threat model relies on elsewhere. What
replaces it, and what it costs, is recorded in
[ADR 0004](../../docs/adr/0004-mobile-in-process-boundary.md). Read it before
changing anything in `lib/platform/`.

Consequences worth knowing before you touch this app:

- **The owner credential never reaches Dart.** It is minted and rotated on the
  Rust side at every unlock and spliced into requests there. There is no token
  file. Do not add one.
- **This client has narrower authority than the desktop.** The `mobile_owner`
  policy rule denies `connection:add`, `connection:enroll`, migrations and gate
  execution. `AppCapabilities.androidPhone` hides the matching UI, so a control
  that reappears will produce a denial rather than work.
- **Vault provisioning is a separate channel** (`keylease_provision`), because
  it cannot be authenticated. It is not reachable through `keylease_call`.
- **`android:allowBackup` must stay `false`.** With the default, Android Auto
  Backup uploads the vault database to the user's Google Drive.
- **`FLAG_SECURE` must stay set** in `MainActivity`. It blocks screenshots and
  the recents-screen thumbnail.

## Build

```sh
source ~/workspace/android-toolchain/env.sh   # Flutter 3.47.2, JDK 17, SDK, NDK
../../scripts/build-android.sh --debug
```

`--release` produces an **unsigned** artifact. That is deliberate: the
repository never falls back to the Android debug key, and the build script fails
if it finds one. Sign where the key lives — Play App Signing, or a one-shot
`apksigner` step on the machine that holds the keystore. Do not materialise a
keystore on a shared build host.

`--full` runs the Rust and Dart checks first. `--aab` builds an app bundle.

The Rust core is rebuilt by Gradle's `preBuild` via
`scripts/build-android-rust.sh`, so a stale `libkeylease_mobile.so` cannot be
packaged. Set `KEYLEASE_SKIP_RUST=1` to reuse the staged one when only Dart
changed.

## ABIs

`arm64-v8a` for devices and `x86_64` for emulators. `armeabi-v7a` is excluded:
Argon2id wants 64 MiB, and asking for that in a 32-bit address space beside
Flutter's own heap is a real OOM risk for a marginal device population.

`abiFilters` in Gradle only constrains `jniLibs`; Flutter's engine libraries
need `--target-platform android-arm64,android-x64`, which the build script
passes. A debug build packages every engine ABI regardless — expected.

Release `.so` files must be 16 KB page-aligned or Android 15 will refuse to load
them. `scripts/build-android-rust.sh` asserts this with `llvm-readelf` rather
than trusting the linker default.

## Tests

```sh
flutter test                      # this app: composition root and adapters
cd ../../packages/leasegate_vault_ui && flutter test   # the shared UI and state
cd ../.. && cargo test -p keylease-mobile              # the FFI boundary
```

The FFI boundary is verified on the host, not on a device: the `rlib`
crate-type lets `crates/keylease-mobile/tests/` call the `extern "C"` surface
directly. Run it under AddressSanitizer too — mismatched deallocation layout is
the dominant defect class there and `cargo test` alone will not see it:

```sh
RUSTFLAGS="-Zsanitizer=address" \
  cargo +nightly test -p keylease-mobile --target x86_64-unknown-linux-gnu
```

## What still needs a real device

There is no `/dev/kvm` on the current build host, so nothing below can be
verified here:

- clipboard auto-clear and its "only if unchanged" behaviour
- `FLAG_SECURE` (screenshots, recents thumbnail)
- biometric unlock and camera QR scanning
- the back gesture and edge-to-edge insets on Android 15
- restoring a desktop backup and browsing the vault

## Not in this version

- **Desktop ↔ phone sync.** The server side exists; no client sync engine does,
  in any language. Move a vault with an encrypted backup for now. A `device_id`
  and the vault's provenance are already recorded at provisioning so a later
  sync engine does not need a migration.
- **Google Workspace setup.** Cut with connection creation; the loopback OAuth
  callback would work in process, but the `mobile_owner` role denies adding
  connections anyway.
- **Multiple vaults on one device.**
- **iOS.** The `staticlib` crate-type is already produced for it; the app is not.
