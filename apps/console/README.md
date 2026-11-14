# KeyLease Console

The web console for a self-hosted `keylease-server`: devices, approvals and the
audit log. It is a static single-page app (React, TypeScript, Vite, TanStack
Router and Query, shadcn/ui) that `keylease-server` serves from its own binary.

Status: scaffold. The pages exist, but only the server health check is wired;
the device, approval and audit APIs arrive with `keylease-server` (phase P2 in
`docs/design/platform-v2-plan-vi.md`).

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
