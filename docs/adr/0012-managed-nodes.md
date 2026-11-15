# ADR 0012: Managed nodes

Status: accepted (P6, replaces the Edge node's policy role)

## Context

An organization wants its rules to hold on every vault its people run
agents on: a VPS running `keylease serve`, or a Mac. Before this, the earlier
Edge node received signed policy bundles. Plain vault nodes had only their
owner's local policy.

## Decision

1. **Joining.**
   - An organization owner or admin creates a one-time enrollment code (24 hours).
   - On the node, the vault owner runs `keylease cloud org join` (master password).
   - The node redeems the code with a request signed by its relay key, and pins
     the server's Ed25519 signing key, which the answer carries.
2. **Policy.**
   - Owners and admins write the organization's node policy: rules with an id,
     an effect, actions, and optionally an agent and a resource prefix.
   - Managed rules **only tighten**: `deny` or `require_approval`. The server
     refuses anything else, and so does the node.
3. **Signing.**
   - The server signs `KEYLEASE-MANAGED-POLICY-V1\n` followed by the payload
     (organization, version, issue and expiry times, rules), with the key it
     uses for its other control artifacts.
   - A policy is valid for 30 days and is signed again, with the same rules
     and a new version, when less than 23 days are left.
4. **Applying.** The daemon fetches the policy every minute. It checks the
   signature against the pinned key, the organization, the expiry, that every
   rule only tightens, and that the version never goes back. It then reports the
   version it runs. Its rules join the vault's policy as `managed_…` rules:
   - their rule version is above every local rule, so a managed
     `require_approval` outranks the vault's own grants and trusts;
   - a deny wins as always;
   - an empty resource prefix means every resource of the vault.
5. **Leaving.**
   - `keylease cloud org leave` (master password) removes the pin and the rules.
   - An admin removing the node only stops new policies. The rules in force stay
     until the owner leaves, so a removal never loosens a vault.
   - An expired copy keeps applying, for the same reason.

## Consequences

- A taken-over server could publish more restrictive rules or stop
  publishing, but it cannot loosen a vault. Managed rules cannot grant
  anything.
- An organization can require approval where the vault's owner had granted
  access. Those approvals cannot be pre-trusted, because a trust is a local rule
  with a lower version.
- The signing key is the server's control signing key
  (`KEYLEASE_CONTROL_SIGNING_KEY_FILE`). Rotating it means the nodes join
  again.
