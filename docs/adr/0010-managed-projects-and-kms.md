# ADR 0010: Managed projects and the server KMS key

Status: accepted (P3 step 2)

## Context

Private projects (ADR 0006, 0009) are end to end encrypted: the server never
holds a key that opens them. CI/CD pipelines and the MCP Gateway cannot work
that way: a workload with only an OIDC token, or the server calling an API for
an agent, needs the server to read the secret. The v2 plan gives organization
projects a second mode, **Managed**, where the server can decrypt.

## Decision

1. **Envelope encryption.** Each Managed project has a data key (32 random
   bytes), wrapped with XChaCha20-Poly1305 by the server's **KMS root key** and
   bound to the organization, project and key version (associated data). The
   root key comes from `KEYLEASE_KMS_ROOT_KEY_FILE` (unpadded base64, mode
   0600); without it Managed projects are unavailable. Cloud KMS and HSM root
   keys are later providers behind the same wrap/unwrap step.
2. **Secrets are KEY=VALUE per environment**, each value sealed with the
   project's current data key and bound to organization, project,
   environment, name and version.
3. **Append-only versions.** Setting, deleting (a tombstone) and restoring
   each add a version; nothing is overwritten, so history and point-in-time
   restore need no extra machinery. Old versions keep their data key version,
   so **rotating** the data key (`rotate-key`, project admins) needs no
   re-encryption.
4. **Access follows the project role** (ADR 0008/teams): `read` lists names and
   reveals values, `write` sets, deletes and restores, `admin` rotates keys and
   reads the audit. Every reveal, change, export and rotation is audited
   (`managed_audit`).

## Consequences

- Whoever runs the server, with the root key, can decrypt Managed projects.
  The console says so; use Private projects for what the operator must not
  read.
- Losing the root key loses every Managed secret: back it up apart from the
  database.
- Change requests for protected environments, machine identities (CI/CD) and
  the MCP Gateway build on this storage in the next steps.
