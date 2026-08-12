# HIP: Human Interactive Protocol

> **Licensing status:** This repository does not currently grant an open-source or commercial software license.
> HIP is separating public interoperability components from hosted product and operational code before applying
> component-specific terms. See [ADR-015](docs/decisions/ADR-015-licensing-and-distribution-boundaries.md) and the
> machine-readable [licensing boundary inventory](docs/licensing-boundaries.json). The inventory is not a license grant.

> **HIP (Human Interactive Protocol)** is an application-layer trust and interaction protocol for verifying digital origin, integrity, and risk evidence across web and virtual-world clients.

[![Protocol](https://img.shields.io/badge/Protocol-Human%20Interactive%20Protocol-2d7ff9)](#what-is-hip)
[![Security](https://img.shields.io/badge/Security-Trust%20%2B%20Identity%20Evidence-0a7f5a)](#security-model)
[![Status](https://img.shields.io/badge/Status-Active%20Development-f39c12)](#project-status)

---

## What is HIP?

HIP stands for Human Interactive Protocol.

HIP helps users, communities, and platforms answer a core question:

**“Can I trust this interaction, and why?”**

Today’s internet stack gives us:

- **TCP** for connectivity
- **TLS** for encrypted transport

HIP adds what those layers do not provide directly:

- **interaction identity evidence** (who initiated what)
- **integrity evidence** (whether interaction artifacts were altered)
- **origin accountability**
- **risk and reputation signals**
- **explainable trust decisions**

HIP is built as a **protocol + platform**, with support for clients such as:

- browser extension integrations
- virtual-world clients, including Second Life HUD workflows
- future partner and community integrations

---

## Why HIP exists

Digital interaction environments increasingly face:

- impersonation and account abuse
- scam and social-engineering workflows
- synthetic or manipulated content
- weak cross-platform attribution
- opaque trust systems users cannot audit

HIP is designed to be:

- **security-first**
- **privacy-aware**
- **cryptographically verifiable**
- **transparent and explainable**
- **provider-agnostic with cryptographic agility**

A valid cryptographic signature can prove origin and integrity, but not automatically intent or safety. HIP combines multiple forms of evidence for better trust outcomes.

---

## Core principles

- **Protocol-first, not platform lock-in**
- **Evidence over black-box scoring**
- **Privacy-minimizing design**
- **Untrusted input model** for network, client, provider, and user inputs
- **Cryptographic agility** for evolving standards

---

## High-level architecture

- **HIP Domain / Protocol Layer**
  - interaction identity assertions
  - evidence normalization
  - trust and risk decision logic
- **HIP Service Layer**
  - APIs and orchestration
  - policy and versioning
- **Client Integrations**
  - browser extension
  - virtual-world and HUD integrations
  - future SDK-oriented consumers
- **Evidence Providers**
  - contribute signals
  - do **not** unilaterally determine final trust outcomes

### Solution structure

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

---

## Build and run locally

```powershell
dotnet restore HIP.slnx
dotnet build HIP.slnx
dotnet test HIP.slnx
```

For normal local development, set `HIP.AppHost` as the Visual Studio startup project and run it. Aspire starts the HIP API, Web/Admin, PostgreSQL, and Redis resources together.

CLI equivalent:

```powershell
dotnet run --project src/HIP.AppHost/HIP.AppHost.csproj --launch-profile http
```

Local service defaults are:

- API: `http://localhost:5099`
- Web/Admin: `http://localhost:5123`
- PostgreSQL container resource: `postgres`
- HIP PostgreSQL database resource: `HipDatabase`
- Redis container resource: `redis`

The browser extension uses production HIP services by default. For local extension development, override its API and website URLs in the extension options.

You can run the API and Web projects separately, but direct project runs must provide PostgreSQL and Redis configuration. HIP does not fall back to local database files or process-local duplicate/replay state:

```powershell
$env:ConnectionStrings__HipDatabase='Host=localhost;Port=5432;Database=hip;Username=hip;Password=<local-password>'
$env:HipInfrastructure__DatabaseProvider='PostgreSQL'
$env:ConnectionStrings__redis='localhost:6379,abortConnect=false'
dotnet run --project src/HIP.ApiService/HIP.ApiService.csproj
dotnet run --project src/HIP.Web/HIP.Web.csproj
```

Before the first AppHost run, configure independent local protection keys in the AppHost user-secrets store. Use values with at least 32 characters; do not use the placeholders as real values:

```powershell
dotnet user-secrets set "Parameters:hip-record-encryption-key" "<generate-a-random-record-key>" --project src/HIP.AppHost/HIP.AppHost.csproj
dotnet user-secrets set "Parameters:hip-privacy-hashing-key" "<generate-a-different-random-hashing-key>" --project src/HIP.AppHost/HIP.AppHost.csproj
```

For CI or deployed environments, supply the same Aspire parameter names through the environment or an approved secret store. API, Web, and worker processes receive them as `HipSecurity__RecordEncryptionKey` and `HipSecurity__PrivacyHashingKey`. HIP rejects missing, shared development, weak, or obvious placeholder values outside Development.

---

## Use cases

- Verifying interaction origin and authenticity
- Detecting impersonation and suspicious behavior patterns
- Integrity checks for shared interaction artifacts and content
- Explainable trust indicators for users and moderators
- Trust and safety augmentation in virtual worlds and web communities

---

## Who HIP is for

- trust and safety engineers
- security engineers
- protocol designers
- identity and reputation researchers
- browser extension developers
- virtual-world platform builders
- open-source contributors focused on safer interaction systems

---

## Project status

HIP is in **active development** as a production-oriented protocol platform.

The current runtime is centered on Aspire:

- the browser extension scans eligible public pages and submits privacy-safe summaries;
- API/Web persist scan, feedback, review, rule, identity, and audit records through `HIP.Infrastructure`;
- PostgreSQL is the normal runtime database, while SQLite and in-memory stores are reserved for explicit tests;
- admin/dashboard pages show live data or clear no-data and not-connected states instead of fabricated activity.

HIP remains a pre-V1 foundation. Authentication, durable worker queues, remaining Redis-backed adapters, normalized hot tables, and external-provider slow-path workers continue to receive production hardening.

---

## Getting started

1. Clone this repository.
2. Follow the build and local-run instructions above.
3. Review the maintained project references under `docs/project-reference/`.
4. Start with protocol/domain components before client integration layers.

---

## Contributing

HIP welcomes contributors who care about:

- secure digital interaction
- privacy-conscious engineering
- protocol correctness
- maintainability and testing
- clear documentation and explainability

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development workflow and submission guidance.

---

## Community and discoverability

Suggested repository topics:

`human-interactive-protocol` `identity` `trust` `trust-and-safety` `reputation` `provenance` `integrity` `cryptography` `digital-signatures` `security` `privacy` `protocol` `browser-extension` `second-life` `virtual-worlds` `risk-analysis` `origin-verification` `open-source`

---

## Security model

- Treat all external, user, provider, and client input as untrusted until validated.
- Minimize sensitive data collection and retention.
- Never treat signature validity as the sole trust truth.
- Keep secrets and identifiers out of logs, tests, and public diagnostics.

If you discover a vulnerability, follow the responsible disclosure process in `SECURITY.md` when present.

---

## Vision

HIP aims to make digital and virtual interactions safer by making trust signals:

- verifiable,
- explainable,
- privacy-aware,
- and portable across ecosystems.

**Human interaction should be more trustworthy than spoofing, scams, and opaque scoring systems.**

---

## License

See `LICENSE` in this repository.
