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
  HIP.LocalHost
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

For normal local development without Docker or Aspire, run the Docker-free local host:

```powershell
dotnet run --project src/HIP.LocalHost/HIP.LocalHost.csproj
```

It starts:

- API: `http://localhost:5099`
- Web/Admin: `http://localhost:5123`

The browser extension should use those same base URLs.

You can still run the API and Web projects separately:

```powershell
dotnet run --project src/HIP.ApiService/HIP.ApiService.csproj
dotnet run --project src/HIP.Web/HIP.Web.csproj
```

The Aspire AppHost project remains available for orchestration, but it requires Docker Desktop/DCP to be healthy. If Aspire appears to do nothing locally, run `docker info` first. If Docker is inaccessible, use `HIP.LocalHost`.

## Status

This repository currently contains the foundation only: solution structure, starter architecture docs, core domain model scaffolding, and first scoring model tests.
