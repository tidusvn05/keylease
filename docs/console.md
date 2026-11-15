# KeyLease Console

The console is the web UI of a self-hosted `keylease-server`
([ADR 0008](adr/0008-server-identity-and-console-sign-in.md)). It shows your
account, its devices and passkeys, the pending approvals of your nodes and
their audit log; it never shows vault secrets.

## Server setting

Set the URL browsers use to reach the server, including any path prefix of
the reverse proxy (the compose setup serves it below `/api`). Passkeys are
bound to its host:

```sh
KEYLEASE_SERVER_PUBLIC_URL=https://vault.example.com/api
```

## Signing in

The first time, from the owner device (the one that ran `keylease cloud init`):

```sh
keylease cloud console
# {"url": "https://vault.example.com/console/#login=…", "expires_at": …}
```

Open the URL once within 15 minutes. Then add a passkey in the console
(Settings → Passkeys) to sign in later without the device. Sessions last 12
hours; sign out ends the current one.

If the console is served somewhere other than the cloud URL + `/console/`,
pass `--console-url`.

## Devices

The console lists the owner device and every node. Revoking a node stops it
from using the relay immediately; the owner device can only be replaced by
recovering the account (`keylease cloud recover`).

## Approvals and audit

A node shows its pending approvals in the console once you turn it on there
([ADR 0011](adr/0011-console-approvals-and-node-audit.md)). Register a passkey
in the console first, then on the node (master password):

```sh
keylease cloud console-approvals enable     # pins the account's passkeys
keylease cloud console-approvals status
keylease cloud console-approvals disable
```

`keylease serve` then reports its pending approvals every few seconds.
**Approvals** lists them per node with the agent, action, resource and the
agent's stated purpose; **Approve** or **Deny** asks for your passkey, and you
can add a trust window the way the node's own approvers do. The node checks
the passkey signature itself before applying the decision, and the list shows
whether it was applied.

After adding a passkey, run `enable` again on each node: a node accepts only
the passkeys it pinned. With `enable --no-audit` the audit stays on the node;
otherwise **Audit log** lists the events every node uploads (the server keeps
the last 50,000 per node).

## Single sign-on

With an OpenID Connect provider (Google Workspace, Microsoft Entra ID, Okta,
Keycloak, …), set:

```sh
KEYLEASE_OIDC_ISSUER=https://accounts.example.com
KEYLEASE_OIDC_CLIENT_ID=keylease-console
KEYLEASE_OIDC_CLIENT_SECRET_FILE=/run/keylease-secrets/oidc_client_secret   # if the client has one
KEYLEASE_OIDC_ALLOWED_DOMAINS=example.com                                   # optional
```

Register the redirect URI `$KEYLEASE_SERVER_PUBLIC_URL/v1/console/sso/callback`
with the provider. The console then offers **Sign in with single sign-on**.
An identity must be **linked** once, from a signed-in console (Passkeys →
Link my single sign-on identity); an unlinked identity signs nobody in. The
flow uses the authorization code with PKCE, `state` and `nonce`, and checks the
ID token against the provider's keys.
