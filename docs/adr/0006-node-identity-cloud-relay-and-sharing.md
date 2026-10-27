# ADR 0006: Node identity, the cloud relay, item sharing and recovery

Status: accepted

## Context

ADR 0005 gave every agent its own identity on a vault node. Two questions were
left open:

- **Which identity owns data?** Two agents on one VPS share that VPS's vault;
  approvals and trusts are per agent, but what data is present at all is a
  property of the machine.
- **How does a node that started standalone relate to a cloud?** A KeyLease
  vault created with `vault init` has its own random root key and can never be
  merged with another vault (`NativeStore::device_identity`). The Cloud already
  stores ciphertext sync mutations, but nothing in the vault node talks to it,
  and its only authentication is the admin token.

The owner's requirements:

1. A workload node (VPS) keeps only its own local data by default. It gets
   anything else only by requesting it and having the owner approve.
2. The owner's personal devices see everything.
3. Sharing is easy. The default unit is one **item**; a **project** can be
   shared as a whole.
4. When a cloud is set up, a VPS's own secrets are backed up so that a dead VPS
   can be recovered; the owner's vault is recoverable too.

## Decision

### Two levels of identity

| Level | Decides | Mechanism |
|---|---|---|
| **Member** (a vault node: the owner's device, a VPS, an Edge) | which data is present | public-key encryption to that member |
| **Agent** (a process on a node) | what is used | policy, approvals and trusts (ADR 0005) |

An agent is named `member/agent`. A shared item on a VPS is an ordinary item
there: every agent still needs its own approval or trust to use it.

Members have two kinds:

- **owner** — the account's personal identity: an Ed25519 signing key and an
  X25519 box key, held by the owner's device(s) and in the recovery kit. It
  approves shares and can read every backup.
- **node** — a workload node with its own Ed25519 and X25519 keys. It holds no
  owner key and receives nothing unless the owner shares it.

### The cloud is a relay that cannot read or forge

The Cloud gains a **relay** API (`/v1/relay/...`). It stores members' public
keys, a mailbox per member and the latest backup object per member and item.
Every payload is sealed (X25519 + HKDF-SHA256 + XChaCha20-Poly1305) to its
recipient and signed (Ed25519) by its sender over the account, sender,
recipient, kind, object, revision and ciphertext digest. Requests are signed by
the member's Ed25519 key over method, path, timestamp and body digest (120 s
window). The admin token is used only to create the account.

The Cloud learns which members exist, who sends what kind of message to whom,
object ids, revisions and sizes. It never sees an item, a purpose, a key or a
recovery code.

### Pairing that a malicious cloud cannot subvert

The owner runs `cloud invite NAME`, which produces a code `LOOKUP-SECRET`. Only
the lookup half is sent to the Cloud (hashed); the secret half stays with the
owner and is typed into the node. The invite stored in the Cloud carries the
owner's public keys and `HMAC(secret, account, owner keys)`; the node verifies
it, so a cloud that substitutes the owner key is detected. The node registers
its keys with `HMAC(secret, account, node keys)`; the owner's device verifies
that tag before it trusts the node's keys, so a cloud that substitutes a node
key is detected too. Until verified, a node cannot receive a share.

### Sharing

- **Item share** (default): the owner seals the item to the node and signs it.
  The owner's daemon republishes it when the item changes and sends a
  revocation when the share is revoked or expires.
- **Project share**: every item in the project, including items added later;
  an item that leaves the project is revoked from the node.
- **Share request**: an agent on a node runs `keylease cloud request PURPOSE`
  (an RPC; any enrolled agent may ask). The request is sealed to the owner.
  The owner approves it by choosing the item (`cloud approve REQ --item ID`),
  which creates an item share, or denies it.

A shared item is imported on the node with a `keylease.cloud_share` extension
and is not backed up by the node (the owner has it). Revocation deletes the
node's copy on its next sync; it cannot unsee a value already delivered, so a
revoked secret must be rotated when the node is not trusted any more.

### Backup and recovery

When a member is linked to a cloud, its daemon backs up each of its own items
(not shared-in copies), sealed to the **owner** key and signed by the member,
and sends tombstones for deleted items. Groups and projects are not part of the
backup: a restored item lands in the default group without a project.

- **A dead VPS:** create a new node with a new invite, then the owner runs
  `cloud restore --from OLD --to NEW`. The owner's device verifies each backup
  object with OLD's key, decrypts it and re-seals it to NEW as a restore
  message; NEW imports the items as its own. OLD can then be removed.
- **A lost personal device:** `cloud init` prints a **recovery kit** once (the
  cloud URL, the account id and a 26-character recovery code). The owner keys
  are stored in the Cloud encrypted under a key derived from the code
  (Argon2id); the Cloud holds only a hash of a lookup value derived from it. On
  a new device, `cloud recover` fetches the kit, decrypts the owner keys and
  restores the owner's own backups into a fresh vault.

### Synchronization

`keylease serve` (and the desktop daemon) runs the relay sync every 60 seconds
while the vault is linked and unlocked, without extending the idle lock:
backups out, owner republishes, node requests out, mailbox in. `cloud sync`
runs one round on demand. Every step is idempotent: messages carry
client-generated ids, the node records applied ids, backups are upserted by
revision.

## Consequences

- A VPS stays useful without a cloud; linking it never merges vaults.
- The owner's device is the only place a share can be decided, because only it
  can decrypt. Approving shares from the Mac app is future work; the CLI does it
  today.
- Full live sync between several personal devices (each one editing the same
  vault) is not part of this ADR. Personal devices recover through the backup
  and recovery kit; a second simultaneously active personal device is future
  work on the existing ciphertext sync mutations.
- Field-level sharing is done by creating an item with only the needed fields.
