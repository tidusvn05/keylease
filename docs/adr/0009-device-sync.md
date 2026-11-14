# ADR 0009: Syncing the owner's devices

Status: accepted (P2 step 2)

## Context

ADR 0006 links one **owner** device and any number of **nodes** (VPSes) to a
relay account; nodes receive read-only copies of what the owner shares.
Someone with a second Mac or a phone needs the whole vault on each device,
editable on each, without giving the server the plaintext.

## Decision

1. **A third member role, `device`.** The owner invites one with
   `keylease cloud invite NAME --device`; the invite and the device's keys are
   bound by the same HMAC tags as a node's, now covering the role, so the
   relay cannot turn a node invite into a device. The owner device verifies
   the device like a node (`cloud_verify_members`).
2. **Star topology through the owner device.** A device sends its changes to
   the owner device; the owner device sends every change to every device. Each
   change is a `sync` message: a whole item, group or project (or an item
   deletion), sealed to the recipient's box key and signed by the sender, as
   every relay message. The relay only allows `sync` between the owner and a
   device, and never to or from a node.
3. **Last writer wins, with history.** An incoming object replaces the local
   one when its `updated_at` is newer (ties: the larger member id). The store
   keeps every item revision, so an overwritten version stays in the item's
   history. A deletion wins over edits made before it; an edit made after a
   deletion wins and comes back.
4. **No echo.** Each member remembers, per peer and object, the revision the
   peer already has (sent or received from it) and sends only newer ones.
5. **What syncs:** items, groups and projects of the vault, Personal items
   included (they are the owner's own devices). Items received from shares or
   bundles stay with their origin and are not synced.

## Consequences

- Every device holds the full vault and works offline; changes meet at the
  owner device, which must sync now and then (the desktop app's daemon does).
- Devices reach each other only through the owner device. A mesh (devices
  verifying each other from an owner-signed roster) can replace the star
  later without changing the message format.
- Field-level merging is not attempted: concurrent edits to the same item
  keep the newer one whole; the older is in history.
- Revoking a device stops its relay access; like a node, it keeps what it had
  (rotate secrets that matter).
