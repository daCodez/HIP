# HIP Containerization Foundation

HIP now has a local container foundation for running the API, Web/Admin UI, and production-like dependency services without replacing the existing Aspire workflow.

## Existing Setup Found

- `src/HIP.AppHost` already runs `HIP.ApiService` and `HIP.Web` through Aspire.
- `HIP.ApiService` and `HIP.Web` already expose `/alive` health endpoints through `MapDefaultEndpoints`.
- No Dockerfiles or Docker Compose file existed before this foundation pass.
- No worker service project exists yet, so queue consumption is intentionally documented as a future worker step.
- `HIP.AppHost` declares Aspire-managed PostgreSQL and Redis resources for Visual Studio local development.
- API/Web project runs now require a PostgreSQL `HipDatabase` connection string. Aspire injects it automatically; direct project runs must set `ConnectionStrings__HipDatabase`.

## Aspire Local Resources

When `HIP.AppHost` is the Visual Studio startup project, Aspire should show:

- `hip-api`: HIP API project resource.
- `hip-web`: HIP Web/Admin project resource.
- `postgres`: PostgreSQL container resource managed by Aspire.
- `HipDatabase`: HIP database resource created from the PostgreSQL container.
- `redis`: Redis container resource managed by Aspire.

PostgreSQL is the active EF Core provider for the API and Web/Admin app when launched through AppHost. This avoids the previous mismatch where a database container was expected but some hosts still used SQLite.

## Services

`docker-compose.yml` defines:

- `hip-postgres`: PostgreSQL container for production-like persistence work.
- `hip-redis`: Redis container for future cache, dedupe, and distributed rate-limit work.
- `hip-queue`: RabbitMQ container as the queue placeholder for future scan ingestion workers.
- `hip-api`: HIP API service built from `src/HIP.ApiService/Dockerfile`.
- `hip-web`: HIP Web/Admin service built from `src/HIP.Web/Dockerfile`.

The Docker Compose API and Web containers use `hip-postgres` through `ConnectionStrings__HipDatabase` and `HipInfrastructure__DatabaseProvider=PostgreSQL`. They no longer mount SQLite data volumes.

## Required Environment Variables

Copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env
```

Then replace the placeholder values:

- `HIP_POSTGRES_DB`
- `HIP_POSTGRES_USER`
- `HIP_POSTGRES_PASSWORD`
- `HIP_RABBITMQ_USER`
- `HIP_RABBITMQ_PASSWORD`
- `HIP_RECORD_ENCRYPTION_KEY`
- `HIP_PRIVACY_HASHING_KEY`

Do not commit `.env`. It is ignored by Git.

## Direct Project Runs

Aspire is the preferred local entry point because it supplies the PostgreSQL connection string and starts dependencies. If you run `HIP.ApiService` or `HIP.Web` directly, set a PostgreSQL connection string first:

```powershell
$env:ConnectionStrings__HipDatabase='Host=localhost;Port=5432;Database=hip;Username=hip;Password=<local-password>'
$env:HipInfrastructure__DatabaseProvider='PostgreSQL'
```

Use user secrets, environment variables, or your local shell profile for the password. Do not commit real database credentials.

## Start Services

From the repository root:

```powershell
docker compose up --build
```

Default local URLs:

- API: `http://localhost:5099`
- Web/Admin: `http://localhost:5123`
- RabbitMQ management UI: `http://localhost:15672`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

## Stop Services

Stop containers without deleting data:

```powershell
docker compose down
```

Stop containers and remove local container volumes:

```powershell
docker compose down -v
```

Use `-v` carefully. It deletes local container data.

## Health Checks

The API and Web Dockerfiles use `/alive` health checks.

Manual checks:

```powershell
Invoke-WebRequest http://localhost:5099/alive
Invoke-WebRequest http://localhost:5123/alive
```

Dependency checks:

```powershell
docker compose ps
```

## Aspire And Docker Compose

Aspire is the Visual Studio/local orchestration path for the .NET projects and local dependency containers.

Docker Compose is the container deployment foundation:

- use Aspire when developing from Visual Studio
- use Docker Compose when validating container startup and local dependency services

The Compose stack does not wipe or replace Aspire configuration.

## Safe Dev Secrets Handling

- Real secrets belong in `.env`, user secrets, or managed secret stores.
- `.env.example` contains placeholders only.
- Compose requires the sensitive values to be supplied.
- Production deployments must use managed secret injection rather than `.env` files.

## Known MVP Limits

- Redis is available in Aspire and Compose but not yet wired into cache, dedupe, or rate limiting.
- RabbitMQ is available as the future queue service but no worker service consumes it yet.
- Container image hardening is basic. Production should add non-root users, SBOM/provenance, vulnerability scanning, and stricter network policies.
- API/Web containers currently run in Development mode for local testing.
