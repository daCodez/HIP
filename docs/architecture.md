# HIP Architecture

HIP uses Clean Architecture so protocol, scoring, reputation, identity, and safety decisions stay independent of transport, storage, and UI details.

## Layers

- `HIP.Domain`: protocol concepts, scoring primitives, reputation primitives, identity models, certificate policies/lifecycle, rule definitions, and safety results.
- `HIP.Application`: use cases, CQRS handlers, certificate enrollment/issuance/public projections, validation boundaries, and application service contracts.
- `HIP.Infrastructure`: PostgreSQL persistence, DNS and safe HTTPS verification, signed metadata/key lifecycle lookup, reputation stores, and external integrations.
- `HIP.ApiService`: public HTTP APIs for lookup, badges, safety routing, and client integration.
- `HIP.Web`: Blazor UI for lookup, safety pages, and future admin tools.
- `HIP.AppHost`: Aspire orchestration entry point.
- `HIP.ServiceDefaults`: shared service defaults, observability, health checks, and resilience configuration.

## Direction

HIP exposes signed, explainable origin and integrity evidence while keeping certificate state separate from risk scoring. Signed live badge and domain-certificate documents fail closed when managed signing or authoritative key verification is unavailable. A signature does not establish safety or reputation.

## Current boundaries

Domain certificate policy and lifecycle rules remain in `HIP.Domain`; enrollment, policy evaluation, issuance, public projection, badge signing, and verification orchestration remain in `HIP.Application`; DNS/HTTPS adapters and EF persistence remain in `HIP.Infrastructure`; hosts provide versioned, rate-limited endpoints; and Blazor/browser-extension clients consume privacy-safe projections.

Private signing keys remain outside these layers behind `IManagedTrustReceiptSigner`. The default implementation is unavailable, so deployment composition must provide approved managed custody, authoritative public key lifecycle state, and an explicit authority/key allowlist. See [ADR-013](decisions/ADR-013-domain-certificate-and-badge-trust-model.md) and [HIP Domain Trust Certificates](domain-trust-certificates.md).
