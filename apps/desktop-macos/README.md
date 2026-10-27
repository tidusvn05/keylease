# KeyLease desktop (native macOS, in progress)

Native Swift port of `apps/desktop-flutter`. Same role in the architecture: a
thin presentation client over the versioned local IPC API served by
`keylease serve` — no crypto, KDBX, policy or connector code lives here.

`KeyLeaseCore` is a SwiftPM package that builds and tests on both macOS and
Linux (the transport is POSIX, not Network.framework, so CI on Linux covers
the wire layer). The SwiftUI app target itself requires a Mac + Xcode.

```sh
swift build && swift test
```


## Layout

```text
Sources/KeyLeaseCore/
├── JSONValue.swift            # dynamic JSON (the Dart `dynamic` counterpart)
├── KeyLeaseError.swift        # typed error codes, mirror of the Dart client
├── RpcAuth.swift              # auth block, spliced in at call time
├── RpcRequest.swift           # the 59 wire commands (frozen by commands.json)
├── AgentTrust.swift           # hand-maintained trust/enroll types (ADR 0005)
├── PasswordRecipe.swift       # hand-maintained; not in `keylease contracts`
├── ClientTokenFile.swift      # regular-file + mode-0600 token validation
├── KeyLeaseRpc.swift          # POSIX AF_UNIX transport, 4 MiB bound
└── Generated/
    └── ContractModels.swift   # generated — do not edit; see header
```

`Tests/KeyLeaseCoreTests` replays the recorded daemon conversations in
`test-vectors/rpc/golden/` byte-for-byte and asserts the wire command list
against `test-vectors/rpc/commands.json`.

## Regenerating

```sh
cargo run -p keylease -- contracts > /tmp/contracts.json
../../scripts/generate-swift-contracts.py /tmp/contracts.json \
    Sources/KeyLeaseCore/Generated/ContractModels.swift
python3 ../../scripts/capture-rpc-golden.py   # only when wire behavior changes
```
