# HIP Containerization Foundation

HIP now has a local container foundation for running the API, Web/Admin UI, and production-like dependency services without replacing the existing Aspire workflow.

## Existing Setup Found

- `src/HIP.AppHost` already runs `HIP.ApiService` and `HIP.Web` through Aspire.
- `HIP.ApiService` and `HIP.Web` already expose `/alive` health endpoints through `MapDefaultEndpoints`.
- No Dockerfiles or Docker Compose file existed before this foundation pass.
- No worker service project exists yet, so queue consumption is intentionally documented as a future worker step.
- Persistence currently uses EF Core SQLite through `HIP.Infrastructure`. PostgreSQL is staged as a local dependency, but it is not the active EF provider until the PostgreSQL persistence patch is added.

## Services

`docker-compose.yml` defines:

- `hip-postgres`: PostgreSQL container for production-like persistence work.
- `hip-redis`: Redis container for future cache, dedupe, and distributed rate-limit work.
- `hip-queue`: RabbitMQ container as the queue placeholder for future scan ingestion workers.
- `hip-api`: HIP API service built from `src/HIP.ApiService/Dockerfile`.
- `hip-web`: HIP Web/Admin service built from `src/HIP.Web/Dockerfile`.

The API and Web containers still store local MVP data in mounted SQLite volumes:

- `hip-api-data`
- `hip-web-data`

This keeps the container foundation small and avoids silently changing repository behavior before a real PostgreSQL migration is implemented.

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

Aspire remains the Visual Studio/local orchestration path for the .NET projects.

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

- PostgreSQL is available as a container but not yet the active EF Core provider.
- Redis is available but not yet wired into cache, dedupe, or rate limiting.
- RabbitMQ is available as the future queue service but no worker service consumes it yet.
- Container image hardening is basic. Production should add non-root users, SBOM/provenance, vulnerability scanning, and stricter network policies.
- API/Web containers currently run in Development mode for local testing.
