# ADR 0011: Console approvals and node audit

Status: accepted (P2, completes console v1)

## Context

Agents run on nodes (a VPS running `keylease serve`, or the owner's Mac), and
their approvals and audit stay there. A person could approve from the macOS
app or from a paired approver (ADR 0005 mode B), but not from the KeyLease
Console. The console is served by `keylease-server`, which holds no vault key
and should not be able to approve on its own: a server taken over must not
turn into an approver for every node.

## Decision

1. **Opt-in per node.** `keylease cloud console-approvals enable` (master
   password) fetches the account's passkeys from the server, as public keys
   with the relying-party ID and origin, and **pins** them on the node. A
   passkey added later counts only after the command is run again. `disable`
   removes the pins. `--no-audit` keeps the audit on the node.
2. **The node reports, the server carries.** Every five seconds the daemon
   sends its pending approvals (metadata, as the approval sheet shows it:
   action, resource, agent, stated purpose, digest, policy version) in a
   request signed with its relay key (`PUT /v1/relay/console/report`), and
   gets back the decisions waiting for it.
3. **Decisions are signed with a passkey.** The server builds the decision
   payload from the node's latest report: account, node, approval, approve or
   deny, request digest, policy version, an optional trust (scope, duration),
   time and a nonce. The browser signs
   `SHA-256("KEYLEASE-CONSOLE-DECISION-V1\n" || payload)` as the WebAuthn
   challenge, with user verification. The server checks the assertion
   against its passkeys (and their counters) before queueing it.
4. **The node checks again.** Before applying a decision the node verifies
   the assertion against its pinned passkeys, origin and relying party, that
   the payload names this account and this node, is at most ten minutes old,
   and names the pending approval's exact digest and policy version. It then
   decides through the same path as the other approvers, audited under
   `console:<credential>` with the passkey's name, and reports the outcome
   (`approved`, `denied`, or `rejected` with a reason).
5. **Audit upload.** About once a minute the node uploads the audit events the
   server does not have yet (by sequence number); the server keeps the last
   50,000 per node, and the console lists them newest first.

## Consequences

- A taken-over server can withhold or delay decisions and show wrong data,
  but cannot approve: it has no pinned passkey's private key, and a replayed
  decision finds nothing pending.
- Approval metadata and audit events of opted-in nodes are stored on the
  server in plaintext. Secrets never are; the stated purpose is shown as
  untrusted text, as on the node.
- Approval latency is the report interval (a few seconds) plus the person.
  Web Push (a later step) tells the person a request is waiting.
- Nodes need `KEYLEASE_SERVER_PUBLIC_URL` on the server (passkeys need it
  anyway).
