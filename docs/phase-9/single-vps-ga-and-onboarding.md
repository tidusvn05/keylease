# Phase 9 single-VPS GA and onboarding

Status: implementation complete; target-VPS acceptance remains

Last updated: 2026-09-06

## 1. Goal and scope

Phase 9 turns the existing self-hosted stack into an installable and observable
single-VPS product. The only supported runtime profile remains:

```text
self_hosted / local_gateway / one Linux VPS / Docker Compose
```

The phase does not add a LeaseGate-managed service. PostgreSQL, Control Plane,
worker, web UI, object storage and the credential-executing Gateway all remain
on infrastructure controlled by the operator.

## 2. Architecture decisions

- `deploy/leasegate` is the stable host lifecycle entry point. It delegates to
  the already guarded Phase 8 backup, upgrade, rollback and diagnostic flows.
- First installation creates mode-0600 secrets, an owner workspace, one agent,
  one local Edge enrollment and an initial signed deny-all policy.
- One-time agent and Edge credentials are parsed into files and removed with
  the installer's private temporary directory. They are never printed or put
  on command-line arguments.
- The local vault accepts an unattended password only through a regular
  mode-0600 file. Interactive initialization remains the default.
- The host monitor publishes a bounded, redacted JSON snapshot. Control Plane
  receives that directory read-only; it never receives `/var/run/docker.sock`.
- `/v1/system/status` requires the administrator credential and marks snapshots
  older than ten minutes unhealthy. It exposes no environment, log, tenant,
  key, credential or image-digest value.
- Host-changing operations stay in the VPS CLI. The browser dashboard is
  deliberately read-only for host state.

## 3. Implementation checklist

Status values are `DONE`, `MANUAL`, `OPTIONAL` and `EXCLUDED`.

| Priority | Status | Capability | Evidence / operator action |
|---|---|---|---|
| P0 | DONE | Unified `install/status/monitor/backup/verify-backup/upgrade/rollback/diagnostics/acceptance` CLI. | `deploy/leasegate`. |
| P0 | DONE | Fresh-install guard refuses an existing environment or installation marker. | `deploy/operations/install.sh`. |
| P0 | DONE | Installer validates Linux/rootful Docker dependencies and requires a DNS domain plus off-host age recipient. | Installer and Phase 8 host preparation. |
| P0 | DONE | Installer creates the first owner, agent, Edge identity and signed deny-all policy. | One-time API responses are handled in a mode-0700 temporary directory. |
| P0 | DONE | Local vault bootstrap reads its password from a mode-0600 non-symlink file. | `keylease vault init --password-file`. |
| P0 | DONE | Initial encrypted backup is created before installation is declared complete. | Backup destination is stored as non-secret host configuration. |
| P0 | DONE | Backup and monitor timers run as the dedicated repository owner, not root. | Phase 9 systemd unit templates. |
| P0 | DONE | Host status reaches the dashboard without a Docker socket mount. | Redacted snapshot, read-only bind mount and authenticated API. |
| P0 | DONE | Stale host snapshots fail closed in the dashboard API. | Ten-minute server-side freshness ceiling. |
| P0 | DONE | Administrator bootstrap credential has a guarded rotation command and restores the previous value if restart fails. | `rotate-admin-token`. |
| P1 | DONE | First-run web form creates an owner workspace and surfaces its routing IDs without persisting the token. | Flutter setup form. |
| P1 | DONE | Acceptance report is machine-readable and explicitly records that real-provider tests are skipped. | `phase-9-acceptance.json`. |
| P0 | MANUAL | Run the installer on a clean disposable VPS with DNS and TCP 80/443 ready. | Archive elapsed time and installation output without secrets. |
| P0 | MANUAL | Move the initial encrypted backup off-host and verify it using the separately held age identity. | Record backup manifest and verification date. |
| P0 | MANUAL | Complete the Phase 8 signed-release upgrade/rollback drill and seven-day soak. | Existing Phase 8 acceptance evidence. |
| P1 | MANUAL | Rotate the bootstrap administrator credential after setup and record only the date. | Never record the credential. |
| P1 | OPTIONAL | Configure an HTTPS alert webhook and an external textfile collector. | No monitoring cluster is added by default. |
| — | EXCLUDED | Automated rotation of data-encryption or policy-signing roots. | Requires an offline re-encryption/trust-transition protocol; replacing files in place would destroy access. |
| — | EXCLUDED | Enterprise identity/SIEM/BYOK, HA, Kubernetes, managed cloud and billing. | Not part of the single-VPS release target. |

## 4. Fresh installation

Run as the dedicated non-root repository owner. DNS must already resolve to the
VPS. Generate the age identity on a separate trusted machine and pass only its
public recipient to the VPS:

```sh
deploy/leasegate install \
  --domain leasegate.example.com \
  --age-recipient 'age1...' \
  --organization 'My organization' \
  --owner 'Owner' \
  --yes
```

The installer uses `sudo` only to install and enable systemd units. Use
`--no-systemd` for disposable environments. Existing `.env`, enrollment
credentials or an installation marker cause a hard failure instead of an
overwrite.

The generated first policy contains no allow rule. This is intentional: the
Gateway becomes healthy and synchronizes its signed policy, but no agent action
is authorized until the operator reviews and activates a narrow rule.

## 5. Lifecycle commands

```sh
deploy/leasegate status
deploy/leasegate monitor
deploy/leasegate backup
deploy/leasegate verify-backup POSTGRES_DUMP CONFIG_TAR EDGE_TAR
deploy/leasegate upgrade deploy/releases/RELEASE_ID

export LEASEGATE_ROLLBACK_CONFIRM=rollback-to-previous-images
deploy/leasegate rollback

deploy/leasegate diagnostics
deploy/leasegate acceptance

export LEASEGATE_ROTATE_ADMIN_CONFIRM=rotate-bootstrap-admin-token
deploy/leasegate rotate-admin-token
```

The age recipient and ciphertext destination are public operational settings in
the mode-0600 Compose `.env`. The age private identity is not installed by the
Phase 9 installer and must not be kept beside the only backup copy.

## 6. Acceptance and exit criteria

The automated acceptance command runs preflight, runtime, monitor, soak and
timer checks. It writes a mode-0600 JSON report and returns non-zero until every
automated row passes:

```sh
deploy/leasegate acceptance
jq . deploy/compose/.state/phase-9-acceptance.json
```

Phase 9 exits only when every P0 `MANUAL` row above has dated evidence, the
report is `pass`, the encrypted backup verifies off-host and the prior Phase 8
signed-release/soak gate is complete. No real provider account is required.
