# KeyLease Console

The web console for a self-hosted `keylease-server`: devices, approvals and the
audit log. It is a static single-page app (React, TypeScript, Vite, TanStack
Router and Query, shadcn/ui) that `keylease-server` serves from its own binary.

Status: v1. Sign-in (device link or passkey), the account overview, devices
(revoke nodes and devices) and passkeys work against `keylease-server`
([docs/console.md](../../docs/console.md)). Approvals and the audit log stay on
each node for now.

`keylease-server` embeds `dist/` at build time (`crates/keylease-server/build.rs`):
run `pnpm build` before building the server, or the server shows a page that
says the console is missing.

## Develop

Requires Node.js 26 LTS and pnpm 12 (`packageManager` in `package.json`).

```sh
cd apps/console
pnpm install
pnpm dev
```

The dev server proxies API calls to `KEYLEASE_SERVER_URL`
(default `http://127.0.0.1:8080`).

See [AGENTS.md](AGENTS.md) for commands, library versions and rules.
