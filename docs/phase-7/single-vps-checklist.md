# Phase 7 single-VPS production checklist

Status: implementation baseline complete; operator acceptance remains

Last updated: 2026-09-06

## 1. Scope lock

The only Phase 7 deployment target is:

```text
self_hosted / local_gateway / one Linux VPS / one PostgreSQL instance
```

Enterprise features and high availability are explicitly excluded from the
Phase 7 exit criteria. Their code may remain available from Phase 6, but an
operator does not need to configure or validate it to declare the single-VPS
profile ready.

Status values used in this file:

- `DONE`: implemented and covered by repository evidence.
- `MANUAL`: must be completed and dated by the VPS operator.
- `TODO`: in scope but not implemented yet.
- `OPTIONAL`: useful but not a release requirement.
- `EXCLUDED`: intentionally outside this profile, not an incomplete item.

When an operator changes a status, add the date and evidence in the Notes
column. Do not mark a manual check complete based only on a code review.

## 2. Release checklist

| Priority | Status | Check | Evidence / Notes |
|---|---|---|---|
| P0 | DONE | Deployment mode is exactly `self_hosted/local_gateway`. | Edge fails closed for every other mode; `single-vps-check.sh` validates `.env`. |
| P0 | DONE | Control Plane liveness does not depend on PostgreSQL. | `GET /api/healthz`. |
| P0 | DONE | Control Plane readiness verifies PostgreSQL. | `GET /api/readyz`; Compose executes `keylease-cloud healthcheck`. |
| P0 | DONE | Gateway readiness requires an active signed policy and available encrypted audit-spool capacity. | Local `GET /readyz`; Compose executes `leasegate-edge healthcheck`. |
| P0 | DONE | PostgreSQL, Control Plane and Gateway have bounded Compose health checks. | `docker compose config`; `single-vps-check.sh runtime`. |
| P0 | DONE | Secret files are non-empty and mode `0600` or stricter. | `single-vps-check.sh preflight`. |
| P0 | DONE | Conflicting audit replay is rejected rather than silently accepted. | PostgreSQL Phase 4 integration test. |
| P0 | DONE | New audit rows have a verifiable predecessor/position chain. | `GET /v1/organizations/{org}/projects/{project}/audit/integrity`. |
| P0 | DONE | PostgreSQL/configuration/Edge state backup is encrypted to an `age` recipient. | `backup.sh`. |
| P0 | DONE | Backup can be decrypted and structurally checked without restoring it. | `verify-backup.sh`; validates `pg_restore --list` and required archive entries. |
| P0 | DONE | Restore rejects archive traversal paths and requires explicit destructive confirmation. | `restore.sh`. |
| P0 | MANUAL | DNS resolves to the VPS and public `/api/readyz` passes with a trusted TLS certificate. | Record date and `single-vps-check.sh runtime` output. |
| P0 | MANUAL | Firewall exposes only SSH, HTTP and HTTPS; Gateway port 8090 remains loopback-only. | Record firewall rules and an external port scan. |
| P0 | MANUAL | Encrypted backups are copied off the VPS automatically. | Record schedule, target and most recent successful object. |
| P0 | MANUAL | A full restore drill succeeds in a disposable environment. | Record date, duration, restored policy version and audit-integrity report. |
| P0 | MANUAL | The administrator and agent bootstrap credentials have been rotated after setup. | Record rotation date; never paste values here. |
| P1 | DONE | Preflight validates Compose, execution mode, secrets and minimum free disk. | `single-vps-check.sh preflight`. |
| P1 | DONE | Runtime status checks all services, PostgreSQL, Control Plane, Gateway and public TLS. | `single-vps-check.sh runtime`. |
| P1 | MANUAL | VPS has automatic OS security updates and a tested reboot procedure. | Record distribution policy and last reboot test. |
| P1 | MANUAL | Disk alerts fire before PostgreSQL/Edge volumes fill. | Recommended warning at 75%, critical at 90%. |
| P1 | MANUAL | Clock synchronization is enabled and healthy. | Record `timedatectl`/NTP evidence; leases depend on correct time. |
| P1 | MANUAL | Logs are retained with size/age limits and contain no credential material. | Record logging configuration and redaction spot-check. |
| P1 | MANUAL | Upgrade and rollback are rehearsed with pinned image/source revisions. | Record tested revision and rollback duration. |
| P1 | MANUAL | Every enabled connector passes one bounded smoke action and revoke/expiry check. | Real provider accounts are operator acceptance, not CI. |
| P2 | DONE | Generate content-addressed image IDs, SPDX SBOM, provenance and optional cosign signature. | Implemented by the Phase 8 release builder; publishing a signed candidate remains manual. |
| P2 | DONE | Add lightweight service metrics plus disk/backup-age textfile metrics. | Implemented by Phase 8 without adding a monitoring cluster to the default stack. |
| P2 | OPTIONAL | Native mobile approval distribution. | Web approval remains sufficient for the single-VPS baseline. |

## 3. Explicitly excluded

| Status | Capability | Reason |
|---|---|---|
| EXCLUDED | SSO/OIDC login, SCIM, role separation and access reviews | Enterprise administration is not required for the current operator model. |
| EXCLUDED | SIEM integration and enterprise compliance workflows | Local redacted audit and integrity verification are sufficient for this phase. |
| EXCLUDED | BYOK/HSM and workload identity federation | File-backed local keys and fixed agent credentials remain the selected profile. |
| EXCLUDED | Push notification and enterprise mobile device management | Approval can use the self-hosted web UI. |
| EXCLUDED | Multiple Control Plane, worker or Gateway replicas | One process of each runs on one VPS. |
| EXCLUDED | Load balancer, PostgreSQL replication and automatic failover | Recovery uses encrypted off-host backup and a documented restore procedure. |
| EXCLUDED | Multi-region disaster recovery | Outside the cost and topology target. |
| EXCLUDED | Vendor-managed Control Plane or Managed Gateway | The execution and credential boundary stays on the operator VPS. |

The default Compose profile leaves `KEYLEASE_SIEM_SECRETS_FILE` empty, so the
worker does not initialize the SIEM exporter. Set it explicitly only after SIEM
is brought back into scope.

## 4. Commands

```sh
# Before first start or after configuration changes
deploy/compose/single-vps-check.sh preflight

# After the stack is running
deploy/compose/single-vps-check.sh runtime

# Create an encrypted backup
export LEASEGATE_AGE_RECIPIENT='age1...'
deploy/compose/backup.sh /encrypted/off-vps/path

# Verify one backup set without replacing state
export LEASEGATE_AGE_IDENTITY=/secure/path/age-identity.txt
deploy/compose/verify-backup.sh \
  postgres-TIMESTAMP.dump.age \
  config-TIMESTAMP.tar.age \
  edge-TIMESTAMP.tar.age

# Check the server-side audit chain
curl --fail --header "Authorization: Bearer $(tr -d '\n' < deploy/compose/secrets/admin_token)" \
  "https://leasegate.example.com/api/v1/organizations/ORG/projects/PROJECT/audit/integrity"
```

Rows written before migration `0005` are reported as
`legacy_unverifiable_event_count`; their original ordering cannot be derived
retroactively. New rows are verified from the stored legacy head onward. An
attacker with complete database and signing-host control can rewrite both data
and its local head, so encrypted off-host backups remain the independent
recovery checkpoint.

## 5. Exit criteria

The single-VPS profile may leave Phase 7 when:

1. Every P0 `MANUAL` row is dated with evidence.
2. No P0 or P1 row is `TODO`.
3. `cargo test --workspace`, Clippy, Compose validation and shell syntax checks pass.
4. `single-vps-check.sh runtime` passes on the target VPS.
5. The most recent off-host backup passes `verify-backup.sh` and one restore
   drill has completed.

Items marked `EXCLUDED` do not participate in this decision.
