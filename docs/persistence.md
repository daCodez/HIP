# HIP Persistence Foundation

HIP uses a SQLite persistence foundation for local development. The Application layer continues to depend on repository interfaces; EF Core and database details live in `HIP.Infrastructure`.

## Development Database

The development connection string is:

```text
Data Source=hip-dev.db
```

`HIP.Web` reads this from `ConnectionStrings:HipDatabase` in `appsettings.Development.json`. If no value is configured, Infrastructure falls back to the same SQLite file name.

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

The first storage implementation uses a JSON-backed `hip_records` table keyed by partition and ID. This keeps the foundation small while preserving clean boundaries for later normalized PostgreSQL storage.

## Database Safety Rules

- Do not use `EnsureDeleted`.
- Do not wipe existing SQLite files.
- Destructive migrations require review before running.
- Private chat logs, private message bodies, form contents, and raw private evidence must not be persisted by default.

The dev app uses safe create behavior for the initial SQLite table. It creates missing storage but does not delete existing data.

## Migrations

No EF migration files are added yet. The initial development foundation uses safe table creation so the schema can stabilize before migration history is introduced.

When migrations are added:

```powershell
dotnet ef migrations add InitialPersistence --project src/HIP.Infrastructure --startup-project src/HIP.Web
dotnet ef database update --project src/HIP.Infrastructure --startup-project src/HIP.Web
```

Review generated migrations before applying them. Stop before any migration that drops tables, columns, or data.

## Future Production Database Plan

SQLite is for development and local testing. Production storage should move to PostgreSQL or another managed database with:

- normalized tables for high-volume entities
- explicit indexes for lookup and review queues
- migration review gates
- backups and retention policies
- audit-log immutability controls
- encryption and secret management through deployment infrastructure
