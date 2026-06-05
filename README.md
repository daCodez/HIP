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

The foundation contains separate API and Blazor web projects.

```powershell
dotnet run --project src/HIP.ApiService/HIP.ApiService.csproj
dotnet run --project src/HIP.Web/HIP.Web.csproj
```

The Aspire AppHost project is present as the orchestration entry point and will be expanded as platform dependencies are added.

## Status

This repository currently contains the foundation only: solution structure, starter architecture docs, core domain model scaffolding, and first scoring model tests.
