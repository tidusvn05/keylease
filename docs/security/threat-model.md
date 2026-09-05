# KeyLease and LeaseGate threat model (Phase 0)

Status: accepted for the local MVP. This document is an engineering baseline,
not an external security review.

## Assets and trust boundaries

The protected assets are master passwords, account/vault/item keys, item
plaintext, connection credentials, dynamic credential material and local
revocation handles, approval intent and lease-use counters.
Opaque IDs, encrypted payloads and redacted operational metadata may be stored
in SQLite. The local service process is the sole trusted plaintext boundary.
CLI, Flutter, agents, connector responses, imported files and all provider
content are untrusted. In Edge mode, cloud is outside the decryption boundary.
LeaseGate-hosted managed gateway mode is explicitly out of scope and is
rejected; the supported execution mode is `self_hosted/local_gateway` and must
never fall back when the local Gateway is unavailable.

## Threats and mandatory controls

| Threat | Control | Residual risk |
|---|---|---|
| Prompt injection in provider content | Content is marked untrusted; policy is deterministic and connector data cannot change grants | An authorized agent may still misuse data within its granted task |
| Confused deputy | Identity/delegation, connection, canonical resource, action and material arguments are bound into every decision and approval | Same-UID malware requires process/user isolation outside KeyLease |
| Lease-token theft | Tokens are random, stored only as SHA-256 hashes, short-lived, max-use and revocable; default debug output is redacted | MVP bearer tokens can be replayed before revocation |
| Dynamic-credential theft | Policy/backend TTL ceilings, one-response delivery, no-store HTTP, encrypted local handles, upstream expiry; SSH certificate is bound to the caller public key | AWS STS and OAuth bearer material can be replayed until upstream expiry; DPoP/mTLS remain disabled |
| Malicious/buggy connector | Typed schemas, canonicalization before authorization, outbound host allowlists, time/size limits and shared conformance tests | Provider compromise is not prevented |
| SSRF/DNS rebinding | Built-ins use fixed HTTPS origins; custom URLs are rejected; redirects are disabled | Resolver/runtime hardening remains platform-dependent |
| Replay/retry | Idempotency key plus vault-keyed canonical request digest; approval consumption and lease issue are atomic; transactional lease reservation; provider idempotency where available | A provider without idempotency can have an ambiguous result after a process crash |
| Concurrent execution | SQLite immediate transactions reserve `max_uses` and idempotency before dispatch | Cross-database copies are outside the boundary |
| Compromised cloud | Edge mode cloud has ciphertext only; keys are derived/wrapped client-side with domain-separated AAD | Traffic/size metadata remains visible |
| Compromised Edge | Attacker can access plaintext while the vault is unlocked; lock zeroizes session keys | Full host compromise is not solved |
| Offline database theft | Argon2id password slot wraps a random root key; per-vault and per-item random keys; AEAD binds identifiers/revision/schema | Weak master passwords remain guessable at KDF cost |
| Rollback/tampering | AEAD AAD plus monotonic revisions and keyed mutation journal; the native backup authenticates its full manifest; malformed state fails closed | Local administrator can restore an internally consistent old database until trusted checkpointing exists |
| Secret leakage in logs/errors | Structured allowlisted audit fields, redaction at connector boundary, no payload logging, and redacted `Debug` for secrets/requests/provider bodies | OS-level memory/crash capture requires deployment hardening |
| Clipboard disclosure | macOS writes only an explicitly requested field, remembers the pasteboard generation, clears it after 30 seconds only if unchanged, and clears it on manual lock, sleep and screen lock | Clipboard managers and other same-user processes may copy the value before clearing |
| OAuth callback interception/forgery | Google setup uses an IPv4 loopback listener on a random port, S256 PKCE, one-time state, exact `drive.file` scope, bounded callback parsing and fixed HTTPS token/metadata origins | A fully compromised browser or unlocked host remains outside the boundary |
| Local IPC spoofing or lock denial-of-service | Mode-0600 Unix socket, peer-UID validation, registered client token on every operation except status, bounded messages and authentication/unlock rate limits | Same-UID malware remains outside this boundary |

## Security invariants

1. Password-derived material encrypts only a root-key slot; password changes do
   not rewrite item ciphertext.
2. Every item has an independently generated key and authenticated envelope.
3. Unknown action, schema version, field or resource is denied.
4. Approval is valid only for one canonical request digest and policy version;
   its decision is audit-atomic and its consumption is atomic with lease issue.
5. Lease expiry, revocation, kill switch and use budget are checked atomically
   immediately before dispatch.
6. Agent-visible output never contains master passwords or upstream connector
   credentials.
7. Audits contain no item values or external content.
8. Lock invalidates the session and all session-bound grants/leases.

## Explicit non-goals

The beta does not defend against a fully compromised unlocked host, supply-chain
compromise, malicious kernel, physical memory extraction, or a user granting an
over-broad policy. Hardware-backed unlock, cloud recovery, DPoP/mTLS
sender-constrained OAuth tokens and sandboxed third-party connectors remain
later-phase controls. SSH certificate public-key possession is the first
supported sender-constrained dynamic credential.
