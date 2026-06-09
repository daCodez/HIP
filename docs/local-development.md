# HIP Local Development

HIP supports two local startup paths:

- `HIP.LocalHost`: Docker-free local runner for day-to-day development.
- `HIP.AppHost`: Aspire orchestration path for container-aware development when Docker Desktop is healthy.

## Recommended Local Runner

Use `HIP.LocalHost` when you want HIP to run locally without Aspire, Docker Desktop, or DCP.

```powershell
dotnet run --project src/HIP.LocalHost/HIP.LocalHost.csproj
```

The runner starts:

- HIP API: `http://localhost:5099`
- HIP Web/Admin: `http://localhost:5123`

Press `Ctrl+C` in the runner terminal to stop both services. The runner kills the child process trees so stale localhost listeners do not remain behind.

Run `dotnet restore HIP.slnx` and `dotnet build HIP.slnx` once after pulling new package or code changes. The local runner starts child services with `--no-build --no-restore` so local startup does not fail just because NuGet.org is temporarily unavailable.

## Visual Studio

For a Docker-free local run, set `HIP.LocalHost` as the startup project.

Use `HIP.AppHost` only when Docker Desktop is running and `docker info` works from the same Windows account that launches Visual Studio.

## Browser Extension Settings

Use these values while running `HIP.LocalHost`:

- HIP API base URL: `http://localhost:5099`
- HIP Web base URL: `http://localhost:5123`

## Aspire/Docker Requirements

`HIP.AppHost` still uses Aspire's DCP orchestration. If Docker Desktop is stopped or inaccessible, Aspire may fail before the dashboard appears.

Before launching `HIP.AppHost`, verify:

```powershell
docker info
```

If `docker info` fails, use `HIP.LocalHost` until Docker Desktop permissions are fixed.

## Known Limits

- `HIP.LocalHost` does not launch PostgreSQL, Redis, RabbitMQ, or other container dependencies.
- `HIP.LocalHost` does not provide the Aspire dashboard.
- OpenTelemetry still writes structured local logs, but OTLP export only runs when an OTLP endpoint is configured.
- The runner is a development convenience, not a production supervisor.
