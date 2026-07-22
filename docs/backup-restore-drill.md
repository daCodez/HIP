# HIP PostgreSQL Backup and Restore Drill

Run this drill in an isolated non-production environment with PostgreSQL client tools installed. The script never drops or overwrites a database. It requires a newly named database containing `_restore_drill_`; `createdb` fails if that database already exists.

## What is backed up

- a PostgreSQL custom-format dump with ownership and ACL restoration disabled;
- operator-maintained key metadata describing active key identifiers, algorithm, creation/activation/retirement dates, rotation order, and secret-store references;
- SHA-256 checksums and a manifest that explicitly says the metadata contains no secret key material.

Do not place encryption keys, hashing keys, signing private keys, passwords, tokens, or recovery secrets in the metadata file or backup directory. Back up secret values through the managed secret/HSM product under separate access controls and recovery procedures.

## Preconditions

1. Confirm source and restore server/cluster identities and current backup retention.
2. Use a least-privilege drill account and a PostgreSQL password file protected by OS permissions. The script uses `PGPASSFILE` so passwords are not command arguments or logs.
3. Create a private output directory on encrypted storage.
4. Prepare and review the non-secret key metadata JSON.
5. Choose a new restore database name such as `hip_restore_drill_20260721`. Never use the production database name.

## Run

```powershell
./eng/Invoke-HipBackupRestoreDrill.ps1 `
  -DatabaseHost localhost `
  -DatabasePort 5432 `
  -SourceDatabase HipDatabase `
  -RestoreDatabase hip_restore_drill_20260721 `
  -DatabaseUser hip_restore_operator `
  -PasswordFile C:\secure\hip.pgpass `
  -KeyMetadataPath C:\secure\hip-key-metadata.json `
  -OutputDirectory D:\hip-drills\2026-07-21 `
  -ConfirmIsolatedRestore
```

The script dumps the source, copies non-secret metadata, hashes both artifacts, creates the isolated target, restores with `--exit-on-error`, and verifies that the encrypted `Records` table is readable. It reports the restored record count without displaying record payloads.

## Verification and evidence

- compare source and restore schema/migration versions;
- compare aggregate counts for identities, trust receipts, scans, licenses, reviews, audits, outbox/inbox, and dead-letter state without exporting payloads;
- start a HIP instance configured only for the restored database and the recovered secret-store keys;
- verify health, decrypt a controlled test record, perform a public lookup, and inspect one owner-scoped/admin record under authorization;
- record timestamps, RPO, RTO, versions, artifact checksums, approver, anomalies, and cleanup confirmation in the operations audit system.

## Cleanup

The script intentionally leaves the isolated database for verification and never deletes it. After evidence is approved, an authorized operator separately drops the exact restore-drill database and removes temporary artifacts according to retention policy. Confirm the source database name and current connections before cleanup.

This checked-in runbook and parser validation do not constitute a completed production restore drill. Production readiness requires dated evidence from the target platform and secret-management system.
