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
Each signature is `ssh:sign` on the key item, risk R2:

- the first connection queues an approval and `ssh` simply waits (120 s by
  default, `--wait-approval` to change it) while you approve in KeyLease;
- approve once for a single login, or with `--trust 30m|1h|6h|1d` to cover
  that key for a window — useful for `git` and scripts that connect repeatedly;
- denying makes the signature fail and `ssh` reports
  `Permission denied (publickey)`.

The approval's arguments contain only the key fingerprint, never the session
data, so it reads the same for every connection with that key. The SSH agent
protocol does not reveal the destination host to the agent, so policy is per
key. Use separate keys for staging and production if they need different
trust.

## Limits

- RSA signatures use `rsa-sha2-256` or `rsa-sha2-512`; legacy SHA-1 `ssh-rsa`
  signatures and RSA keys under 2048 bits are refused.
- Agent forwarding (`ssh -A`) forwards this agent. Do not forward it to hosts
  you do not trust: they can request signatures (each still needs your
  approval or an active trust).
- The agent CLI runs as your user. It cannot read the key, but while a trust is
  active it can make the agent sign for that key.
