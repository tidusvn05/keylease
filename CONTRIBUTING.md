# Contributing

Thanks for helping. KeyLease guards secrets, so changes are reviewed with the
security model in mind; small, focused pull requests get merged fastest.

## Before you start

- Security vulnerabilities go through [SECURITY.md](SECURITY.md), not issues.
- For a new feature or a change to how approvals, trust, crypto or identity
  work, open an issue first. Decisions are recorded in [`docs/adr/`](docs/adr/).
- Read [docs/architecture.md](docs/architecture.md) for the map of the code.
  `KeyLeaseService` is the only layer that touches storage, policy or
  connectors; the CLI, MCP server, gateway and apps are adapters around it.

## Development

Rust (the toolchain is pinned in `rust-toolchain.toml`):

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check            # dependency advisories and licenses
```

The PostgreSQL tests in `crates/keylease-cloud` run when
`KEYLEASE_TEST_DATABASE_URL` points at a disposable database; CI provides one.

The Flutter packages and the Swift apps are checked separately; see the
Development section of the [README](README.md). CI runs only the Rust checks
today, so say in the pull request how you tested app changes.

## Commits and releases

Write commit subjects as [Conventional Commits](https://www.conventionalcommits.org/)
(`feat: …`, `fix: …`, `docs: …`); the changelog and release notes are generated
from them. Releases are cut by the maintainer as described in
[docs/releasing.md](docs/releasing.md).

## Rules for changes

- Never log, return or store a secret value in plaintext outside the vault.
  Tests use generated keys and fake values.
- A new agent-facing tool or command must not return a secret; if it must
  disclose one, it goes through the reveal path and its approval.
- Update the threat model or an ADR when you change a security boundary, and
  the docs page for any command or flag you change.
- Keep the RPC contract and `test-vectors/rpc/commands.json` in sync.

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), as section 5 of that license describes.
