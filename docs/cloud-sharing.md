# Cloud: share with your VPS, back up, recover

Link your vaults to a self-hosted **KeyLease Cloud** to:

- **share** an item, or a whole project, from your own device with a VPS;
- let an agent on a VPS **ask** you for an item, and approve it on your device;
- **back up** a VPS's own secrets, so a dead VPS can be rebuilt;
- **recover** your own vault on a new device with a recovery kit.

The Cloud is a relay that cannot read anything: every payload is encrypted to
its recipient's key and signed by its sender. A VPS keeps only its own data
until you share something with it. The design is in
[ADR 0006](adr/0006-node-identity-cloud-relay-and-sharing.md).

```text
 your laptop (owner) ───signed, sealed───►  KeyLease Cloud  ◄───signed, sealed─── VPS (node)
   decides shares,                         public keys, mailboxes,              its own items,
   holds the owner key                     sealed backups — no keys             shared copies
```

| Role | What it holds | What it can do |
|---|---|---|
| **owner** (your laptop) | the owner keys; all your items | invite and remove nodes, share, approve requests, read every backup, restore |
| **node** (a VPS) | its own keys; its own items; copies you shared | ask for items, back up its own items (sealed to you) |

Agents keep their own identities (ADR 0005): on a VPS with two agents, both see
the items shared with that VPS, and each still needs its own approval or trust
to use one.

## 1. Run a cloud

The Cloud is `keylease-cloud` (PostgreSQL), as in the
[single-VPS install](self-hosted-vps.md), or the image
`ghcr.io/tidusvn05/keylease-cloud`. Put it behind HTTPS. You need its admin
token (`KEYLEASE_ADMIN_TOKEN_FILE`) once, to create your account.

## 2. Link your laptop as the owner

```sh
keylease cloud init --url https://cloud.example.com --admin-token-file ./admin.token --name laptop
```

It asks for your master password and prints a **recovery kit** once: the
cloud URL, your account id and a 28-character code. Store it offline (a
password manager on another device, or paper). Without it, a lost laptop means
the backups cannot be opened.

## 3. Add a VPS

On the laptop:

```sh
keylease cloud invite vps-prod        # prints a one-time code (30 minutes) and your fingerprint
```

On the VPS (its vault already set up, see [use case 2](use-cases.md#2-agents-on-a-vps-self-trust)):

```sh
keylease --db /var/lib/keylease/vault.sqlite cloud join --url https://cloud.example.com
```

It asks for the master password and the code, and prints the owner
fingerprint: it must match the one the laptop showed. Then, on the laptop,
`keylease cloud sync` verifies the VPS's keys and `keylease cloud nodes`
lists it.

Only half of the code is sent to the Cloud. The other half proves to the VPS
that the owner keys are yours and proves to your laptop that the VPS's keys
are the VPS's, so a cloud that swaps keys is caught on either side.

`keylease serve` (and the macOS app's daemon) syncs every minute while the
vault is unlocked. `keylease cloud sync` runs a round immediately.

## 4. Share

```sh
keylease cloud share ITEM_ID --to vps-prod             # one item (the default)
keylease cloud share ITEM_ID --to vps-prod --ttl 7d    # ends by itself
keylease cloud share --project billing --to vps-prod   # every item of a project, now and later
keylease cloud shares                                  # what is shared, with whom
keylease cloud unshare SHARE_ID
```

On the VPS the item appears in the group `group_cloud_shared`, marked with the
`keylease.cloud_share` extension. Changes you make on the laptop reach it on
the next sync; an item you remove from the project, delete or unshare is
deleted from the VPS. Treat shared copies as read-only: an edit on the VPS is
overwritten by your next change.

Unsharing stops future copies; it cannot make the VPS forget a value it
already had. When you stop trusting a VPS, remove it and rotate what it had.

## 5. Let an agent ask

An agent on the VPS needs no master password:

```sh
keylease cloud request "deploy the billing service" --hint "stripe live key"
```

On the laptop:

```sh
keylease cloud requests                                  # syncs, then lists who asked for what
keylease cloud approve REQUEST_ID --item ITEM_ID --ttl 1h
keylease cloud deny REQUEST_ID
```

Approving creates an item share for the VPS that asked. The agent then finds
the item with `keylease entries search` and uses it through `keylease ssh`,
`db` or `run`, which still ask for the agent's own approval.

## 6. Backups and a dead VPS

Once linked, every member backs up its own items, sealed to the owner key: the
VPS backs up the secrets it created (not the copies you shared), and the
laptop backs up its items, verified nodes and shares. Deleting an item
deletes its backup. Groups and projects are not backed up; restored items land
in `group_cloud_restored`.

When a VPS dies:

```sh
keylease cloud invite vps-new                      # on the laptop; join from the new VPS as in step 3
keylease cloud sync
keylease cloud restore --from vps-prod --to vps-new
keylease cloud remove vps-prod                     # its shares end; it can no longer sync
```

Re-share what the old VPS received from you (its shares stay listed under the
old node).

## 7. A lost laptop

On the new device, create a vault, then:

```sh
keylease cloud recover --url https://cloud.example.com --account ACCOUNT_ID
```

It asks for the master password of the new vault and the recovery code, then
restores your items, your verified nodes and your shares. The new device is
the owner from then on; `keylease cloud sync` resumes everything.

## Commands

| Command | Who | Does |
|---|---|---|
| `cloud init` | owner | link as the owner; print the recovery kit |
| `cloud invite NAME` | owner | one-time code for a node |
| `cloud join` | node | join with a code |
| `cloud nodes`, `cloud remove NODE` | owner | verified nodes; remove one |
| `cloud share`, `shares`, `unshare` | owner | item or project shares |
| `cloud request PURPOSE` | node agent | ask the owner (RPC, no master password) |
| `cloud requests`, `approve`, `deny` | owner (node: own requests) | decide requests |
| `cloud restore --from M [--to NODE]` | owner | restore a member's backup |
| `cloud recover` | new owner device | recovery kit |
| `cloud status`, `cloud sync`, `cloud unlink` | both | state, sync now, forget the link |

Every command except `cloud request` asks for the master password.

## What the Cloud sees

The account id, each member's name and public keys, who sends which kind of
message to whom and when, object ids, revisions and sizes, and the hash of the
recovery lookup. It never sees an item, a title, a purpose, a key or the
recovery code. Message and backup payloads are bound (AEAD and signature) to
the account, sender, recipient, kind, object and revision, so the Cloud can
withhold or delay them but cannot alter, redirect or replay one as something
else.

## Limits

- Full live sync between two personal devices editing the same vault is not
  supported; a second device recovers from the backup.
- Approving share requests is done from the CLI; the macOS app does not show
  them yet.
- A node removed from the cloud keeps the copies it already had.
- The node is trusted with what you share: a fully compromised VPS can read
  every item shared with it while its vault is unlocked.
