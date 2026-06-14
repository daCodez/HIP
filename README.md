# HIP

HIP stands for Human Identity Protocol.

HIP is a trust and origin verification layer for the internet. It sits above TCP and TLS:

- TCP connects devices.
- TLS encrypts the connection.
- HIP verifies trust, origin, reputation, and risk.

HIP is intended to help users understand whether a website, link, sender, file, app, or piece of content can be trusted. It provides identity verification, origin verification, trust scoring, reputation scoring, signed content verification, risk detection, safety warnings, public lookup, live trust badges, and self-healing rule creation.

## Solution Structure

```text
src/
  HIP.AppHost
  HIP.ApiService
  HIP.Web
  HIP.Application
  HIP.Domain
  HIP.Infrastructure
  HIP.ServiceDefaults

tests/
  HIP.Tests

clients/
  browser-extension
  second-life-hud

docs/
  architecture.md
  scoring.md
  rules-engine.md
  privacy.md
  protocol.md
```

## Build

```powershell
dotnet restore HIP.slnx
dotnet build HIP.slnx
dotnet test HIP.slnx
```

## Run

For normal local development, set `HIP.AppHost` as the Visual Studio startup project and run it. Aspire starts the HIP API and Web/Admin projects together.

CLI equivalent:

```powershell
dotnet run --project src/HIP.AppHost/HIP.AppHost.csproj --launch-profile http
```

Aspire starts:

- API: `http://localhost:5099`
- Web/Admin: `http://localhost:5123`
- PostgreSQL container resource: `postgres`
- HIP PostgreSQL database resource: `HipDatabase`
- Redis container resource: `redis`

The browser extension should use those same base URLs.

You can still run the API and Web projects separately, but direct project runs must provide PostgreSQL configuration because HIP no longer falls back to a local SQLite file:

```powershell
$env:ConnectionStrings__HipDatabase='Host=localhost;Port=5432;Database=hip;Username=hip;Password=<local-password>'
$env:HipInfrastructure__DatabaseProvider='PostgreSQL'
dotnet run --project src/HIP.ApiService/HIP.ApiService.csproj
dotnet run --project src/HIP.Web/HIP.Web.csproj
```

The Aspire AppHost is the primary local orchestration entry point.

## Status

HIP now has a local development runtime centered on Aspire:

- the browser extension scans eligible public pages automatically and submits privacy-safe summaries;
- API/Web persist scan, feedback, review, rule, identity, and audit records through `HIP.Infrastructure`;
- PostgreSQL is the normal runtime database, while SQLite and in-memory stores are reserved for explicit tests;
- admin/dashboard pages should show live data or clear no-data/not-connected states instead of fake activity.

This is still an MVP foundation, not production-ready. Production auth, durable worker queues, Redis-backed app caches/dedupe/rate-limit adapters, normalized hot tables, and external-provider slow-path workers remain future hardening work.
