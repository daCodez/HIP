# HIP Architecture

HIP uses Clean Architecture so protocol, scoring, reputation, identity, and safety decisions stay independent of transport, storage, and UI details.

## Layers

- `HIP.Domain`: protocol concepts, scoring primitives, reputation primitives, identity models, rule definitions, and safety results.
- `HIP.Application`: use cases, CQRS handlers, validation boundaries, and application service contracts.
- `HIP.Infrastructure`: persistence, DNS lookup, signed metadata retrieval, reputation stores, and external integrations.
- `HIP.ApiService`: public HTTP APIs for lookup, badges, safety routing, and client integration.
- `HIP.Web`: Blazor UI for lookup, safety pages, and future admin tools.
- `HIP.AppHost`: Aspire orchestration entry point.
- `HIP.ServiceDefaults`: shared service defaults, observability, health checks, and resilience configuration.

## Direction

HIP should expose signed, explainable trust results. API responses that influence user safety should eventually be signed by HIP so clients can verify that results were not altered.

## Initial Boundaries

The foundation starts with domain models and tests. API persistence, live badge rendering, browser extension behavior, and Second Life HUD behavior are later milestones.
