# Phase 8 single-VPS operations and release automation

Status: implementation complete; target-VPS acceptance remains

Last updated: 2026-09-06

## 1. Scope

Phase 8 automates the Phase 7 release gate for exactly one Linux VPS running
`self_hosted/local_gateway`. It does not introduce enterprise identity, SIEM,
HSM, multiple replicas, load balancing or database failover.

The deployment remains Docker Compose. Rust services expose bounded Prometheus
text metrics; host automation is POSIX shell plus systemd. Release artifacts
are local content-addressed Docker image IDs, SPDX SBOMs, checksums and a small
provenance document.

The VPS must use rootful Docker. Rootless Docker remaps the ownership of
bind-mounted mode-0600 secret files, so the non-root service users cannot read
them; `prepare-host.sh` rejects that configuration explicitly.

## 2. Implementation checklist

Status meanings are `DONE`, `MANUAL`, `OPTIONAL` and `EXCLUDED`.

| Priority | Status | Capability | Evidence / operator action |
|---|---|---|---|
| P0 | DONE | Runtime base images are pinned to multi-architecture registry digests. | Compose and all runtime Dockerfiles. |
| P0 | DONE | A release is built only from a clean Git tree and addressed by immutable image IDs. | `deploy/operations/build-release.sh`. |
| P0 | DONE | Every release contains a portable compressed image archive, three SPDX JSON SBOMs, provenance, release environment and SHA-256 manifest. | Release output directory. |
| P0 | DONE | Optional cosign blob signing and mandatory-signature policy are enforced. | `LEASEGATE_COSIGN_KEY`, `LEASEGATE_REQUIRE_SIGNATURE`. |
| P0 | DONE | Database migration runs against a disposable clone before upgrade. | `migration-dry-run.sh`; live database is read using `pg_dump`, never mutated by the dry-run. |
| P0 | DONE | Upgrade requires preflight, migration dry-run and encrypted backup. | `upgrade.sh`. |
| P0 | DONE | Failed upgrade attempts image rollback and never rewinds the database automatically. | Previous image IDs are captured before first Phase 8 rollout. |
| P0 | DONE | Manual rollback requires explicit confirmation and creates another encrypted backup. | `rollback.sh`. |
| P0 | DONE | Backup writes and validates a checksum manifest; optional identity makes scheduled backup verify immediately. | `backup-TIMESTAMP.sha256`. |
| P0 | DONE | Host monitor checks six services, Control Plane/Gateway readiness, disk, backup age and public TLS certificate expiry. | `monitor.sh`. |
| P0 | DONE | Alert webhook is optional, HTTPS-only and loaded from a mode-0600 file. | Alert contains only fixed status codes, no logs or secrets. |
| P0 | DONE | Diagnostic archive excludes env/secrets/database and redacts sensitive log lines. | `diagnostics.sh`; output mode 0600. |
| P1 | DONE | Control Plane and Gateway expose Prometheus text metrics without tenant or credential values. | `/api/metrics` and loopback `127.0.0.1:8090/metrics`. |
| P1 | DONE | Host metrics use node-exporter textfile format without requiring Prometheus in the default stack. | `leasegate.prom`. |
| P1 | DONE | Daily backup and five-minute monitor systemd units are supplied but not auto-enabled. | `deploy/systemd`. |
| P1 | DONE | Host preparation validates Linux architecture and dependencies before creating configuration. | `prepare-host.sh --check/--prepare`. |
| P0 | MANUAL | Install `age`, Syft and cosign from trusted packages/releases. | Record versions and package provenance. |
| P0 | MANUAL | Generate and verify one signed release on the target build host. | Archive `SHA256SUMS`, signature, SBOMs and provenance. |
| P0 | MANUAL | Run the migration dry-run against a current production backup. | Record release ID, schema version and duration. |
| P0 | MANUAL | Exercise upgrade and rollback with a disposable copy of VPS state. | Record downtime and runtime-check output. |
| P0 | MANUAL | Install/edit systemd operations environment and enable both timers. | Record `systemctl list-timers` output. |
| P0 | MANUAL | Confirm the daily backup is off-host and verified using a separate age identity. | Do not keep the only identity next to the only backup. |
| P1 | MANUAL | Connect `leasegate.prom` to an existing node-exporter textfile collector or equivalent local collector. | No monitoring cluster is required. |
| P1 | DONE | Monitor persists a consecutive-health soak counter and resets it on failure. | `soak-status.sh` requires seven fresh days by default. |
| P1 | MANUAL | Complete the automated seven-day soak on the target VPS. | Archive `soak-status.sh` output and incidents. |
| P1 | OPTIONAL | Configure an HTTPS alert webhook. | Local systemd failures remain visible without it. |

## 3. Release flow

```text
clean Git revision
      |
      v
build three pinned-base images
      |
      +--> SPDX SBOM + provenance + SHA256SUMS + optional cosign signature
      |
      v
clone current PostgreSQL --> run candidate migrations --> discard clone
      |
      v
encrypted backup (+ optional immediate verification)
      |
      v
apply immutable image IDs --> runtime checks
      |
      +-- failure --> previous images (database is never silently restored)
```

Only additive/backward-compatible migrations may be used while image rollback
is supported. A release needing a destructive migration must define a separate
maintenance procedure and cannot use the automatic rollback claim.

## 4. Commands

```sh
deploy/operations/prepare-host.sh --check
deploy/operations/prepare-host.sh --prepare

# Build host: Syft is required. Set cosign variables to require signing.
export LEASEGATE_COSIGN_KEY=/secure/cosign.key
export LEASEGATE_REQUIRE_SIGNATURE=1
deploy/operations/build-release.sh v0.2.0

# VPS: validate signature, clone/migrate DB, back up, then deploy.
export LEASEGATE_COSIGN_PUBLIC_KEY=/secure/cosign.pub
export LEASEGATE_REQUIRE_SIGNATURE=1
export LEASEGATE_AGE_RECIPIENT='age1...'
export LEASEGATE_AGE_IDENTITY=/secure/age-identity.txt
deploy/operations/upgrade.sh deploy/releases/v0.2.0

# Explicit image rollback; database is not rewound.
export LEASEGATE_ROLLBACK_CONFIRM=rollback-to-previous-images
deploy/operations/rollback.sh

deploy/operations/monitor.sh
deploy/operations/soak-status.sh
deploy/operations/diagnostics.sh
```

To install timers, first copy and edit the operations environment, then install
the units. The installer deliberately does not enable them:

```sh
sudo deploy/systemd/install.sh /opt/leasegate --apply
sudoedit /etc/leasegate/operations.env
sudo systemctl enable --now leasegate-backup.timer leasegate-monitor.timer
```

## 5. Metrics

The following endpoints/outputs contain only operational values:

- `https://DOMAIN/api/metrics`: process, database readiness and contract version.
- `http://127.0.0.1:8090/metrics`: Control Plane connection, active policy and
  encrypted audit-spool usage.
- `/var/lib/leasegate-ops/leasegate.prom`: service count, readiness, filesystem
  usage and latest encrypted-backup age.

Do not expose Gateway port 8090 publicly. Prefer the node-exporter textfile
collector or another existing local collector for the host metrics file.

## 6. Explicitly excluded

- OIDC/SCIM, enterprise roles and access reviews.
- SIEM and enterprise compliance workflows.
- BYOK/HSM and workload federation.
- Multiple service replicas, load balancers and PostgreSQL failover.
- Kubernetes, multi-region deployment and vendor-managed execution.

These are not Phase 8 completion requirements.

## 7. Exit criteria

Phase 8 exits when every P0 `MANUAL` row has dated evidence, a signed candidate
has passed dry-run/upgrade/rollback on disposable state, both timers have run
successfully, and a seven-day single-VPS soak has no unresolved P0/P1 incident.
No real provider account is needed for repository CI; connector acceptance
remains an operator smoke test from Phase 7.
