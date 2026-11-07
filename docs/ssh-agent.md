# SSH without handing keys to an agent

Step 2 of [ADR 0005](adr/0005-agent-trust-and-secret-use.md). KeyLease acts
as an OpenSSH agent: `ssh`, `git`, `scp`, `rsync` and `ssh-keygen -Y sign` work
unchanged, but the private key stays inside the KeyLease service. The agent
CLI (and the model behind it) only ever sees command output.

## Store the key

Create a **SSH Key** item (`core.ssh_key`) with the OpenSSH private key in its
`private_key` field. A passphrase-protected key also needs the `passphrase`
field; it is decrypted only after a signature is authorized. Keys imported from
1Password or KeePass keep working if they land in those fields.

Remove the key file from disk once it is in the vault. Only the `.pub` file is
needed afterwards, to tell `ssh` which key to offer.

## Use it

One command, nothing to configure:

```sh
keylease ssh deploy@staging.example.com 'systemctl status app'
GIT_SSH_COMMAND="keylease ssh" git pull
```

`keylease ssh` starts a private, single-use agent socket, runs OpenSSH with
`IdentityAgent` pointing at it, and removes it when `ssh` exits. All `ssh`
options pass through.

For tools that read `SSH_AUTH_SOCK`, run a long-lived agent instead:

```sh
keylease ssh-agent --agent-socket ~/.keylease/run/ssh-agent.sock
export SSH_AUTH_SOCK=~/.keylease/run/ssh-agent.sock
ssh-add -L          # lists the vault's public keys
```

Both use the client given by `KEYLEASE_AGENT_ID` / `KEYLEASE_CLIENT_TOKEN_FILE`
(see `docs/agent-approvals.md`), so run them with the agent's enrolled identity.

## Approval

Listing public keys (`ssh:list_keys`) is part of an enrolled agent's baseline.
Each signature is `ssh:sign` on the key item, risk R2 (R3, at most one hour of
trust, when the item's environment is `production`):

- the first connection queues an approval and `ssh` simply waits (120 s by
  default, `--wait-approval` to change it) while you approve in KeyLease;
- approve once for a single login, or with `--trust 30m|1h|6h|1d` to cover
  that key for a window — useful for `git` and scripts that connect repeatedly;
- denying makes the signature fail and `ssh` reports
  `Permission denied (publickey)`.

The approval's arguments contain the key fingerprint and, with OpenSSH 8.9 or
later, the destination host key, never the session data. OpenSSH tells its agent
which host each connection authenticates to (`session-bind@openssh.com`: the
host key, signed over the session identifier); KeyLease relays that to the
service, which verifies the host's signature and that the login being signed
belongs to that session. The approver sees `[host SHA256:…]` before the agent's
purpose (and `via forwarded agent on …` when the agent is forwarded), and an
approval for one host does not sign for another. A time-boxed trust still
covers the key for every host; pin the key (below) to restrict it. Older
clients and `ssh-keygen -Y sign` send no binding, and the decision is on the key
alone, as before.

## Pin a key to its hosts

An SSH key item with a `host_keys` field signs only logins to those hosts:

```sh
keylease ssh-pin ITEM_ID deploy.example.com        # scans its host keys
keylease ssh-pin ITEM_ID SHA256:…                  # or name a fingerprint
keylease ssh-pin ITEM_ID --clear                   # sign for any host again
```

`ssh-pin` runs as the owner (master password). With a host name it fetches the
keys with `ssh-keyscan` and prints their fingerprints: compare them with the
server's (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`) before relying on
them. The field is a list, one host key per line, as a `SHA256:…` fingerprint,
an OpenSSH public key or a `known_hosts` line; you can also edit it by hand.

A pinned key:

- refuses, without asking, a login to any other host;
- refuses when the client sends no session binding (OpenSSH before 8.9) and
  any request that is not an SSH login, such as `ssh-keygen -Y sign`;
- refuses agent forwarding through a host that is not pinned too: to allow
  `ssh -A bastion` then `ssh app`, pin both.

A field with text but no usable line pins the key to nothing.

## Short-lived certificates

Instead of adding an agent key to every server's `authorized_keys`, servers can
trust a certificate authority kept in the vault. The CA private key never
leaves the service; each `keylease ssh --cert` generates a key for that run and
the service certifies it for five minutes.

```sh
keylease ssh-ca init "Ops CA" --principal deploy --principal ops
```

This (owner, master password) creates an Ed25519 CA as an SSH key item with a
`ca_principals` field, in the current directory's project, and prints its
public key. On each server:

```sh
echo 'ssh-ed25519 AAAA… Ops CA' | sudo tee /etc/ssh/keylease_ca.pub
echo 'TrustedUserCAKeys /etc/ssh/keylease_ca.pub' | sudo tee -a /etc/ssh/sshd_config
sudo systemctl reload ssh
```

Then the agent logs in with:

```sh
keylease ssh --cert CA_ITEM_ID deploy@app.example.com 'systemctl status app'
GIT_SSH_COMMAND="keylease ssh --cert CA_ITEM_ID" git pull
keylease ssh-agent --cert CA_ITEM_ID      # renews the certificate as it expires
```

- Issuing is `ssh:issue_cert` on the CA item: R2 (R3 for a production item),
  so the first login asks and Enter trusts it for an hour like any other
  request. The approver sees `[certificate for deploy, ops valid 300s]`.
- The certificate names only principals from `ca_principals`; `--principal`
  narrows it, and asking for another principal is refused. sshd lets a
  certificate log in as a user only if that user is one of its principals
  (or is listed in `AuthorizedPrincipalsFile`).
- `--cert-ttl` sets the lifetime, at most an hour. The certificate permits a
  terminal (`permit-pty`) and nothing else: no agent, port or X11 forwarding.
- Its key id, which sshd logs on each login, names the agent, the grant (the
  trust or approval id) and the CA item: `keylease agent=agent_ops
  grant=trust_… ca=item_…`.
- The CA item is never offered as an identity and never signs anything but
  certificates, since a CA signature is a login to every server that trusts it.

Unlike a vault key, the per-run key is held by the `keylease ssh` process, so a
program running as the agent's user could read it from memory. It is worth
nothing to a server once the certificate expires.

## Limits

- RSA signatures use `rsa-sha2-256` or `rsa-sha2-512`; legacy SHA-1 `ssh-rsa`
  signatures and RSA keys under 2048 bits are refused.
- Agent forwarding (`ssh -A`) forwards this agent. Do not forward it to hosts
  you do not trust: they can request signatures (each still needs your
  approval or an active trust). The approver sees the forwarding host, and a
  pinned key refuses forwarding through a host it is not pinned to.
- RSA certificate authorities are not supported; `ssh-ca init` makes Ed25519.
- The agent CLI runs as your user. It cannot read the key, but while a trust is
  active it can make the agent sign for that key.
