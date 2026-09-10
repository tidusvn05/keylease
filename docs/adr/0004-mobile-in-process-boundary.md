# ADR 0004: The mobile client runs the vault in process

Status: accepted

## Context

Through Phase 9 there is exactly one trusted plaintext boundary. `docs/security/threat-model.md`
states it plainly:

> The local service process is the sole trusted plaintext boundary. CLI, Flutter,
> agents, connector responses, imported files and all provider content are
> untrusted.

That is enforced by a process split. `keylease serve` holds the decrypted keys;
Flutter reaches it over a Unix socket at `$HOME/.keylease/run/keylease.sock` and
authenticates with a registered client token, and the daemon validates both the
socket peer's uid and that token on every call except `status`.

Android cannot host that daemon. There is no supported way for an app to run a
persistent background process that survives the app being killed, and API 29+
W^X rules forbid executing a bundled binary from the app's writable data
directory. The alternative — reaching a daemon over the network — was rejected:
no vault operation is exposed by any network service in this repository, and
adding one would mean designing an authenticated remote vault API, which is a
larger change and contradicts the local-first posture.

## Decision

On Android the Rust core runs **inside the app process**, behind a C ABI
(`crates/keylease-mobile`). Dart calls it through `dart:ffi` from a dedicated
worker isolate.

The wire format does not change. Both transports dispatch through
`keylease_rpc::dispatch_value`, so the socket and the FFI cannot answer the same
request differently; `crates/keylease-rpc/tests/parity.rs` pins that.

## Consequences

### What is lost

**The process boundary is gone on this platform.** Flutter and the decrypted
vault share an address space. The threat-model row *"Compromised Edge — attacker
can access plaintext while the vault is unlocked"* now also describes a
compromised UI layer on mobile, because there is no longer a separate process to
compromise.

This is a real reduction, not a relabelling, and it is accepted because the
alternative is no mobile client at all.

### What replaces it

| Desktop control | Mobile equivalent |
|---|---|
| Mode-0600 Unix socket, peer-uid check | The Android application sandbox: the vault file is in app-private storage readable only by this uid |
| Registered client token on every call | The owner credential is held in Rust and spliced in there; it never reaches the Dart heap or the filesystem — see below |
| Lock on sleep / screen lock | Lock on `AppLifecycleState.paused`/`hidden`/`detached`, plus an idle timer the desktop does not have |
| Clipboard cleared after 30s if unchanged | The same semantics in Kotlin (`SecurityPlugin.kt`), scheduled on a `Handler` so it outlives the Flutter engine |
| — | `FLAG_SECURE`: no screenshots, no recents thumbnail |
| — | `android:allowBackup="false"`: the vault is never uploaded to Google Drive |

The credential handling is **stronger** than desktop, not weaker. On desktop the
token is a file Dart reads on every call. Here it is minted at unlock,
rotated each time (`register_local_owner_client` is an upsert), kept in a
`Zeroizing<String>` on the Rust side, and never persisted.

### Authority is narrower on mobile

A phone is more easily lost and less easily inspected than a desktop, so it does
not get the desktop's authority. `mobile_owner` (`keylease-service`,
`mobile_owner_rule`) drops `connection:add`, `connection:enroll`, migrations and
gate execution, while keeping `connection:disconnect` and `connection:revoke` —
the phone is often the device to hand when something must be cut off.

Two independent gates enforce this: the policy rule above, and `RpcCapabilities`
passed into every dispatch.

### Provisioning is a separate channel

Creating a vault, restoring a backup and registering the first owner credential
cannot be authenticated — before they run there is no credential. They are a
separate enum with a separate dispatcher and a separate FFI symbol
(`keylease_provision`), so no `command` string routes to them and the socket
transport cannot reach them however it is built.

### Accepted residual risks

- **Response strings are not zeroised.** `serde_json::Value` and the field views
  inside `handle_rpc` hold revealed secrets in ordinary `String`s. This is
  identical to the current desktop posture and is not made worse here. A real
  fix is a `keylease-service`-wide change that would benefit both.
- **A compromised, unlocked device is out of scope**, as on every other
  platform.
- **A standalone vault created on the phone can never be merged** with another
  device, because `initialize` mints a random account root key. The UI defaults
  to restore-from-backup and records provenance so a future sync engine can
  refuse to enrol an unmergeable vault.

## Alternatives rejected

- **`uniffi` → Kotlin → MethodChannel.** Would materialise every revealed secret
  as a `java.lang.String` on the ART heap: immutable, un-zeroisable, relocated
  by the copying collector, and present in heap dumps. A direct hit on the
  "Secret leakage in logs/errors" row.
- **`flutter_rust_bridge`.** The surface is one `String -> String` function over
  an existing JSON protocol. Using it would either add codegen for no benefit or
  require a second definition of the protocol — the drift `keylease-rpc` exists
  to prevent.
- **A network-reachable vault API.** See Context.
