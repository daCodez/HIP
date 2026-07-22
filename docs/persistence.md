# HIP Persistence Foundation

HIP uses a PostgreSQL persistence foundation for local development and runtime hosts. The Application layer continues to depend on repository interfaces; EF Core and database details live in `HIP.Infrastructure`.

## Development Database

The preferred development path is Aspire. `HIP.AppHost` starts PostgreSQL and injects the `HipDatabase` connection string into the API and Web/Admin app.

For direct project runs, set:

```text
ConnectionStrings__HipDatabase=Host=localhost;Port=5432;Database=hip;Username=hip;Password=<local-password>
HipInfrastructure__DatabaseProvider=PostgreSQL
```

Do not commit real database credentials. Use Aspire, user secrets, environment variables, or local shell profile settings. HIP no longer silently falls back to a SQLite file when `HipDatabase` is missing.

## Repository Pattern

Repository interfaces stay in `HIP.Application`. EF-backed implementations live under `HIP.Infrastructure/Persistence/Repositories`.

Current persisted record categories include:

- HIP identities
- reputation profiles
- reputation events
- rules
- rule simulation results
- review items
- generated admin review queue signals
- appeals
- reputation override requests
- audit logs
- risk finding reports
- self-healing rule candidates
- weighted browser/banner feedback

The first storage implementation uses a JSON-backed `hip_records` table keyed by partition and ID. This keeps the foundation small while preserving clean boundaries for later normalized PostgreSQL tables.

## Encrypted Record Storage

HIP protects generic record payloads before writing them to the `Json` column. The current development implementation stores an encrypted envelope using AES-256-GCM with a configured `HipSecurity:RecordEncryptionKey`.

Development fallback constants remain inside the low-level services for isolated tests and explicit direct Development runs. The Aspire AppHost does not embed or pass those values. Configure its secret parameters before first use:

```powershell
dotnet user-secrets set "Parameters:hip-record-encryption-key" "<generate-a-random-record-key>" --project src/HIP.AppHost/HIP.AppHost.csproj
dotnet user-secrets set "Parameters:hip-privacy-hashing-key" "<generate-a-different-random-hashing-key>" --project src/HIP.AppHost/HIP.AppHost.csproj
```

For a planned privacy-key rotation only, the AppHost can optionally propagate one former key to all HIP processes:

```powershell
dotnet user-secrets set "Parameters:hip-legacy-privacy-hashing-key" "<the-former-privacy-hashing-key>" --project src/HIP.AppHost/HIP.AppHost.csproj
```

The legacy privacy parameter is optional and is not registered when it is absent, so existing local setups do not acquire a new startup requirement. Remove it after the documented grace period. Direct or deployed hosts can configure the bounded collection with `HipSecurity__LegacyPrivacyHashingKeys__0` through `__7`; do not configure a compromised former key.

The values must be independent and at least 32 characters. Outside local
Development, infrastructure registration immediately rejects missing values,
the built-in development values, weak values, and obvious placeholders before
the host begins handling requests. Deployed hosts should obtain secrets from
their platform secret store and expose them as
`HipSecurity__RecordEncryptionKey` and `HipSecurity__PrivacyHashingKey`.

Existing plaintext development rows remain readable so local data created before this hardening patch can still be migrated or inspected. New writes use the encrypted envelope.

## Consumer History Owner-Index Backfill

HIP-0205 stores new consumer risk findings and appeals twice in one atomic write: once in the existing global encrypted partition and once in a privacy-hash owner partition. Consumer requests read only bounded owner partitions; they never decrypt the global history to discover ownership.

Records created before that change require one explicit, idempotent backfill. In the Aspire dashboard, the `hip-owner-index-backfill` project uses explicit start and does not run with normal HIP startup. Before starting it:

1. Confirm the PostgreSQL volume is the intended HIP volume and take the normal database backup/checkpoint.
2. Keep every record-encryption key needed by retained history configured, including the legacy key when applicable.
3. Start `hip-owner-index-backfill` once from the Aspire dashboard and inspect its completion totals. It exits after processing all bounded pages and never opens an HTTP endpoint.
4. Re-running it is safe: matching owner copies are counted as existing, not duplicated.

The operation decrypts only authenticated records from exact global partitions, validates record IDs and privacy hashes, and copies the existing encrypted envelope. It does not rewrite or delete the global record. Reports without a consumer owner are counted as unowned and remain global-only. A mismatched, ambiguous, plaintext, or corrupt owner copy fails the operation instead of guessing.

Normal report and appeal writes take a shared PostgreSQL advisory transaction lock. Each bounded backfill batch takes the exclusive counterpart, so live writes cannot race an index copy; unrelated HIP storage remains available. Do not remove legacy encryption keys until the completion totals and consumer-history queries have been verified.

## Database Safety Rules

- Do not use `EnsureDeleted`.
- Do not wipe existing PostgreSQL volumes, schemas, or local database data.
- Destructive migrations require review before running.
- Private chat logs, private message bodies, form contents, and raw private evidence must not be persisted by default.

The dev app uses safe create behavior for the initial PostgreSQL table. It creates missing storage but does not delete existing data.

Outside local Development, HIP never calls `EnsureCreated` or
`MigrateAsync`. Application startup is validation-only: it requires compiled
migrations, checks the EF migration history, and fails with an actionable error
when any migration is pending. Schema changes are a separate operator action.

## Migrations

The initial `InitialHipSchema` migration creates the generic encrypted-record
table, typed browser-scan table, dashboard aggregate table, and their indexes.
Every future model change must include a reviewed migration.

Provide the target PostgreSQL connection string only to the migration command:

```powershell
$env:HIP_DATABASE_CONNECTION_STRING = "Host=<host>;Port=5432;Database=<database>;Username=<operator>;Password=<secret>"
dotnet ef database update --project src/HIP.Infrastructure --startup-project src/HIP.Web
Remove-Item Env:HIP_DATABASE_CONNECTION_STRING
```

Generate a future migration with the same explicit environment variable:

```powershell
$env:HIP_DATABASE_CONNECTION_STRING = "Host=localhost;Port=5432;Database=hip_design;Username=<operator>;Password=<secret>"
dotnet ef migrations add <MigrationName> --project src/HIP.Infrastructure --startup-project src/HIP.Web --output-dir Persistence/Migrations
Remove-Item Env:HIP_DATABASE_CONNECTION_STRING
```

The design-time factory refuses to run without
`HIP_DATABASE_CONNECTION_STRING`; migration tooling does not start the HIP
application or fall back to a source-controlled credential.

Review the generated `Up` and `Down` operations before applying them. Stop
before any unapproved operation that drops or rewrites tables, columns, or data.
Back up the target database and test rollback before a production migration.

Databases previously created through the Development-only `EnsureCreated`
path do not have EF migration history. Do not point a production deployment at
one and apply the initial migration blindly: back it up and use a reviewed
baseline/adoption procedure because its tables already exist.

## Production Database Plan

PostgreSQL is the current durable database target. Production storage still needs hardening work:

- normalized tables for high-volume entities
- explicit indexes for lookup and review queues
- migration review gates
- backups and retention policies
- audit-log immutability controls
- encryption and secret management through deployment infrastructure
