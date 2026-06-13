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

Development defaults are intentionally marked as development-only. Outside local Development, startup refuses the shared default key so production deployments must provide real secret material through configuration or a secret store.

Existing plaintext development rows remain readable so local data created before this hardening patch can still be migrated or inspected. New writes use the encrypted envelope.

## Database Safety Rules

- Do not use `EnsureDeleted`.
- Do not wipe existing PostgreSQL volumes, schemas, or local database data.
- Destructive migrations require review before running.
- Private chat logs, private message bodies, form contents, and raw private evidence must not be persisted by default.

The dev app uses safe create behavior for the initial PostgreSQL table. It creates missing storage but does not delete existing data.

Outside local Development, HIP no longer uses `EnsureCreated`. If EF migrations are present, startup applies them with `MigrateAsync`. If no migrations exist, startup fails closed with a clear error so production-like environments cannot silently create unmanaged schemas.

## Migrations

No EF migration files are added yet. The initial development foundation uses safe table creation so the schema can stabilize before migration history is introduced. Production deployments must add and review migrations before running outside Development.

When migrations are added:

```powershell
dotnet ef migrations add InitialPersistence --project src/HIP.Infrastructure --startup-project src/HIP.Web
dotnet ef database update --project src/HIP.Infrastructure --startup-project src/HIP.Web
```

Review generated migrations before applying them. Stop before any migration that drops tables, columns, or data.

## Production Database Plan

PostgreSQL is the current durable database target. Production storage still needs hardening work:

- normalized tables for high-volume entities
- explicit indexes for lookup and review queues
- migration review gates
- backups and retention policies
- audit-log immutability controls
- encryption and secret management through deployment infrastructure
