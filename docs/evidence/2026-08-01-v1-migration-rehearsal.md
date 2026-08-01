# V1 migration and rollback rehearsal evidence — 2026-08-01

## Scope

The live HIP database was not modified. The root-owned backup
`hip-20260801T220627Z.dump` was restored into a disposable PostgreSQL 17
container on a Docker `--internal` network. A self-contained Linux EF Core 10.0.4
migration bundle was built from revision `9a9178e`, checksummed, and executed by
the deployed API runtime image from revision
`e00b47312bfa331eb788a6768019b286c4a17e43`.

## Observed result

- Backup size: 96,457 bytes.
- Migration bundle SHA-256:
  `acad8f3586717f848b19300032e08b686a1c6151978572c41748078eb18cee4d`.
- Migration history before rehearsal: 8 rows, latest
  `20260727085800_AddDomainCertificateMonitoring`.
- Controlled downgrade target:
  `20260726151934_AddDomainCertificateApplications`.
- Migration history after downgrade: 7 rows; all three monitoring columns were
  absent as expected.
- Migration history after reapplication: 8 rows; the three monitoring columns
  and `IX_hip_domain_enrollments_monitoring_due` were restored.
- The one restored domain-enrollment row remained present before and after.
- The migration runner had no external network route, ran read-only with all
  capabilities dropped and `no-new-privileges`, and used only an ephemeral drill
  credential.
- The temporary database container, internal network, logs, and uploaded bundle
  were removed after the assertions passed.

## Rollback finding and remediation

The schema rollback path passed, but the deployment host retained prior source
release directories without retaining prior immutable HIP application images;
the Compose-generated `latest` images had been overwritten. The VPS Compose
model now assigns every HIP-built image a full-revision tag. Operators must
retain the current and previously approved tags so normal application rollback
can redeploy the prior artifact while keeping a backward-compatible expanded
schema, as required by `docs/deployment.md`.
