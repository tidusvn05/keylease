# Security policy

KeyLease holds secrets and decides when agents may use them, so we treat
security reports as the highest-priority work.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:
**Security → Report a vulnerability** on this repository (private
vulnerability reporting). Include:

- the affected component (`keylease` CLI or daemon, MCP server, gateway,
  remote approver, desktop or mobile app, LeaseGate Cloud/Edge) and the commit;
- what an attacker needs (local user, enrolled agent, network access to the
  gateway, a prompt the model reads, …) and what they gain;
- steps or a proof of concept against a test vault, never against real data.

We aim to acknowledge a report within 3 working days and to agree on a fix
and disclosure date with you. Credit is given in the release notes unless you
prefer otherwise.

## Supported versions

The project is pre-1.0. Fixes land on `main` and in the next release; older
releases are not patched.

## Scope

In scope, among others:

- reading a secret value without an approval that covers it, or using an
  approval or trust beyond its agent, action, resource, digest or expiry;
- an MCP tool or broker (`ssh`, `db`, `run`) returning or leaking a secret, or
  running commands it was not approved for;
- bypassing OAuth, PKCE, connect codes, token rotation or revocation in the
  gateway, or signature checks in the remote approver API;
- weaknesses in vault encryption, key derivation, storage or audit integrity.

Known limits that are documented as such are not vulnerabilities on their
own: results a tool is meant to return reach the model's provider; a
"read-only" database query is advisory; `run_with_secrets` gives the child
process the value. See the [threat model](docs/security/threat-model.md),
[MCP](docs/mcp.md) and [gateway](docs/mcp-gateway.md) pages.
