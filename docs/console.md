# KeyLease Console

The console is the web UI of a self-hosted `keylease-server`
([ADR 0008](adr/0008-server-identity-and-console-sign-in.md)). It shows your
account, its devices and passkeys; it never shows vault secrets.

## Server setting

Set the URL browsers use, so passkeys can be bound to it:

```sh
KEYLEASE_SERVER_PUBLIC_URL=https://vault.example.com
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
