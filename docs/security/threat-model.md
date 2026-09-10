# KeyLease and LeaseGate threat model (through Phase 7 single-VPS beta)

Status: accepted for the local MVP. This document is an engineering baseline,
not an external security review.

## Assets and trust boundaries

The protected assets are master passwords, account/vault/item keys, item
plaintext, connection credentials, dynamic credential material and local
revocation handles, approval intent and lease-use counters.
Opaque IDs, encrypted payloads and redacted operational metadata may be stored
in SQLite. On desktop and Edge the local service process is the sole trusted
plaintext boundary; CLI, Flutter, agents, connector responses, imported files
and all provider content are untrusted. In Edge mode, cloud is outside the
decryption boundary.

**On Android that process boundary does not exist.** The platform cannot host a
persistent daemon, so the Rust core runs inside the app process behind a C ABI
and the UI shares its address space. The application sandbox replaces the
socket's uid check as the isolation mechanism. This is a deliberate reduction,
recorded with what replaces it in
[ADR 0004](../adr/0004-mobile-in-process-boundary.md).
LeaseGate-hosted managed gateway mode is explicitly out of scope and is
rejected; the supported execution mode is `self_hosted/local_gateway` and must
never fall back when the local Gateway is unavailable.

## Threats and mandatory controls

| Threat | Control | Residual risk |
|---|---|---|
| Prompt injection in provider content | Content is marked untrusted; policy is deterministic and connector data cannot change grants | An authorized agent may still misuse data within its granted task |
| Confused deputy | Identity/delegation, connection, canonical resource, action and material arguments are bound into every decision and approval | Same-UID malware requires process/user isolation outside KeyLease |
| Lease-token theft | Tokens are random, stored only as SHA-256 hashes, short-lived, max-use and revocable; default debug output is redacted | MVP bearer tokens can be replayed before revocation |
| Dynamic-credential theft | Policy/backend TTL ceilings, one-response delivery, no-store HTTP, encrypted local handles and upstream expiry; SSH is public-key bound; OAuth DPoP requires a verified Ed25519 proof and matching provider `cnf.jkt` | AWS STS and non-DPoP OAuth bearer material can be replayed until upstream expiry; mTLS-bound token delivery is not enabled |
| Stolen mobile session | Private device key stays in platform secure storage, biometric gates signing, challenge is one-use/two-minute and signed sessions expire after five minutes | A fully compromised unlocked mobile OS is outside the boundary |
| Forged enterprise identity | Exact OIDC issuer/audience/signature/expiry/subject validation against bounded HTTPS JWKS; SCIM token is digest-only and cannot grant privileged roles | IdP compromise and deployment-specific browser authorization flow remain external trust dependencies |
| Audit/SIEM tampering | Per-project predecessor/position hash chain, conflicting-replay rejection, on-demand integrity verification, signed compliance evidence, HMAC-signed HTTPS SIEM batches and optimistic delivery cursor | Database owner can rewrite both events and the local head; encrypted off-host checkpoints or external anchoring are needed for independent evidence |
| Split-brain workers | Renewable PostgreSQL leader lease gates maintenance, retention and SIEM delivery | PostgreSQL availability/consensus is an operator responsibility |
| Single-VPS outage | Encrypted off-host PostgreSQL/config/Edge backups, non-destructive backup verification and guarded restore runbook | One VPS has no live failover; recovery time depends on replacement infrastructure and the operator's restore drill |
| Malicious/buggy connector | Typed schemas, canonicalization before authorization, outbound host allowlists, time/size limits and shared conformance tests | Provider compromise is not prevented |
| SSRF/DNS rebinding | Built-ins use fixed HTTPS origins; custom URLs are rejected; redirects are disabled | Resolver/runtime hardening remains platform-dependent |
| Replay/retry | Idempotency key plus vault-keyed canonical request digest; approval consumption and lease issue are atomic; transactional lease reservation; provider idempotency where available | A provider without idempotency can have an ambiguous result after a process crash |
| Concurrent execution | SQLite immediate transactions reserve `max_uses` and idempotency before dispatch | Cross-database copies are outside the boundary |
| Compromised cloud | Edge mode cloud has ciphertext only; keys are derived/wrapped client-side with domain-separated AAD | Traffic/size metadata remains visible |
| Compromised Edge | Attacker can access plaintext while the vault is unlocked; lock zeroizes session keys | Full host compromise is not solved |
| Offline database theft | Argon2id password slot wraps a random root key; per-vault and per-item random keys; AEAD binds identifiers/revision/schema. On Android `allowBackup="false"` plus `dataExtractionRules` keep the database out of Google Drive backup and device-to-device transfer, so obtaining it still requires the device | Weak master passwords remain guessable at KDF cost |
| Rollback/tampering | AEAD AAD plus monotonic revisions and keyed mutation journal; the native backup authenticates its full manifest; malformed state fails closed | Local administrator can restore an internally consistent old database until trusted checkpointing exists |
| Secret leakage in logs/errors | Structured allowlisted audit fields, redaction at connector boundary, no payload logging, and redacted `Debug` for secrets/requests/provider bodies | OS-level memory/crash capture requires deployment hardening |
| Clipboard disclosure | macOS writes only an explicitly requested field, remembers the pasteboard generation, clears it after 30 seconds only if unchanged, and clears it on manual lock, sleep and screen lock. Android does the same in Kotlin, scheduled outside the Flutter engine so the clear survives the engine being killed, and marks the clip sensitive so the system suppresses its paste preview | Clipboard managers and other same-user processes may copy the value before clearing |
| Mobile device loss | Vault is app-private and excluded from cloud backup and device transfer; `FLAG_SECURE` blocks screenshots and the recents thumbnail; locking on background and on idle drops the session keys; the `mobile_owner` role cannot create connections, run migrations or execute gates, so a stolen unlocked phone cannot mint new connector credentials | A phone unlocked and in the attacker's hands while the vault is open is outside the boundary, as on any platform |
| Mobile local IPC spoofing | Not applicable: there is no socket. The vault is opened in process, the owner credential is minted per unlock and never leaves the Rust side, and vault provisioning is a separate dispatcher that no request command can reach | Any code running inside the app process shares the address space; see ADR 0004 |
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
9. Vault provisioning is unauthenticated by construction and therefore never
   reachable from an authenticated request channel; it lives in a separate
   request type with its own dispatcher.
10. A local owner client's authority follows its role: only the desktop owner
    may run agent handoffs or vault migrations.

## Explicit non-goals

The beta does not defend against a fully compromised unlocked host, supply-chain
compromise, malicious kernel, physical memory extraction, or a user granting an
over-broad policy. Hardware-backed unlock, vendor cloud recovery, mTLS
sender-constrained OAuth token delivery and sandboxed third-party connectors
remain outside this beta. SSH public-key possession and verified OAuth DPoP are
the supported sender-constrained dynamic credential paths.
