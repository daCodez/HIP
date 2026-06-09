# HIP

HIP stands for Human Interactive Protocol.

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

You can still run the API and Web projects separately:

```powershell
dotnet run --project src/HIP.ApiService/HIP.ApiService.csproj
dotnet run --project src/HIP.Web/HIP.Web.csproj
```

The Aspire AppHost is the primary local orchestration entry point.

## Status

This repository currently contains the foundation only: solution structure, starter architecture docs, core domain model scaffolding, and first scoring model tests.
