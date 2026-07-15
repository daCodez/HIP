---
title: "HIP Protocol - Master Product Plan and Technical Specification"
author: "Prepared for the HIP project"
date: "July 12, 2026"
---

# Document Control

| Field | Value |
|---|---|
| Product | HIP - Human Identity Protocol |
| Repository | `daCodez/HIP` |
| Document version | 1.0 |
| Prepared date | July 12, 2026 |
| Intended reader | Codex, developers, security reviewers, product owners |
| Delivery status | Codex-ready implementation specification |
| License | Apache License 2.0 |

## Purpose

This document is the single working plan for continuing HIP. It is not a request to rebuild the solution. Codex must inspect the current repository first, preserve completed work, and implement only confirmed gaps.

HIP is a trust and origin verification layer for the internet. It sits above TCP and TLS:

- TCP connects devices.
- TLS protects data in transit.
- HIP evaluates identity, origin, reputation, evidence, and risk.

HIP must help a person understand whether a website, URL, sender, file, image, app, message, or other content can be trusted. A valid signature proves origin and integrity. It does not automatically prove safety.

# 1. Codex Operating Contract

## 1.1 Required safety procedure

Before changing any file, Codex must:

1. Read `AGENTS.md`, this specification, `README.md`, and the relevant existing source files.
2. Run `rtk git status --short` and `rtk git log -5 --oneline`.
3. Never reset, clean, delete, regenerate, or overwrite the repository to make the task easier.
4. If the working tree is clean, create a small checkpoint commit before a major work package.
5. If the working tree is not clean, preserve it. Create a timestamped patch backup and a list of untracked files before editing.
6. Make one small, testable work package at a time.
7. Run targeted tests first, then the full solution tests when practical.
8. Report every changed file, the reason, tests run, test results, and remaining risks.

## 1.2 Hard rules

- Do not rebuild features that already exist.
- Do not remove existing fields, routes, UI controls, or configuration without a documented migration.
- Do not replace the approved HIP logo or existing icon set.
- Preserve the current brand assets and their integrity tests.
- Do not show fake dashboard activity. Use live data or a clear no-data state.
- Do not put secrets, tokens, passwords, encryption keys, or provider credentials in source code.
- Use environment variables, .NET user secrets for local development, and a production secret store.
- Do not paste real secrets into chat, logs, commits, tests, fixtures, or screenshots.
- Every new method must be covered by a test. Test private behavior through the public surface where possible.
- Add XML documentation to every new method and public type.
- Add comments for security-sensitive, performance-sensitive, privacy-sensitive, and non-obvious logic.
- Validate all untrusted input at the application boundary.
- Log safely. Never log raw private content, credentials, cookies, tokens, full keys, or private messages.
- Prefer current C# 14 language features only when they improve clarity, safety, or performance.
- Use design patterns only when they reduce coupling or make security boundaries clearer.
- Use cancellation tokens for I/O and long-running operations.
- Use `TimeProvider` instead of calling system time directly in testable application code.

## 1.3 Preferred patterns

Use these patterns where they fit:

- Strategy for scoring, signing, provider, and policy algorithms.
- Factory for cryptographic providers, external evidence providers, and client adapters.
- Adapter for SSL Labs, Google Web Risk, VirusTotal, DNS, and platform integrations.
- Facade for browser scanning and public trust lookup.
- Repository for persistence behind application interfaces.
- Specification for rule conditions and data queries.
- Pipeline or chain of responsibility for evidence collection and score calculation.
- Outbox pattern for reliable internal events.
- Circuit breaker, timeout, retry, and bulkhead policies for external providers.
- Singleton only for immutable, thread-safe, stateless services or caches designed for singleton lifetime.

# 2. Verified Technical Baseline

## 2.1 Current platform

The current repository targets .NET 10 and C# 14. .NET 10 is an active LTS release. The repository currently uses Aspire 13.4.2. Aspire 13.4.6 is the latest stable patch found during preparation of this document.

Recommended platform baseline:

| Area | Target |
|---|---|
| Runtime | .NET 10 LTS, latest supported patch |
| Language | C# 14 |
| Orchestration | Aspire 13.4.x, update through controlled patch upgrades |
| Web UI | Blazor interactive server components |
| API | ASP.NET Core minimal APIs with versioned route groups |
| Database | PostgreSQL |
| Distributed cache | Redis |
| Observability | OpenTelemetry through HIP.ServiceDefaults |
| Local DNS lab | CoreDNS container |
| Unit test framework | Keep the repository's existing test framework and conventions |
| Browser testing | Playwright for UI and extension flows |
| Containers | Aspire-managed local containers; production-ready container images later |

A patch update from Aspire 13.4.2 to 13.4.6 should be its own work package. It must include a checkpoint, package lock review, build, full tests, local Aspire startup, PostgreSQL persistence test, Redis test, CoreDNS test, and browser extension smoke test.

## 2.2 Current repository structure

The current solution contains:

```text
src/
  HIP.AppHost
  HIP.ApiService
  HIP.Application
  HIP.Domain
  HIP.Infrastructure
  HIP.SandboxWorker
  HIP.ServiceDefaults
  HIP.Web

tests/
  HIP.Tests

clients/
  browser-extension
  second-life-hud

docs/
```

Current working capabilities include:

- Aspire local orchestration.
- PostgreSQL persistence.
- Redis integration.
- CoreDNS local domain verification lab.
- Public domain lookup and badge routes.
- Browser score, link scan, and stored scan result routes.
- Site-safety scoring and privacy-safe browser observations.
- Weighted user feedback.
- Review queues and appeals foundations.
- JSON rules, simulations, and self-healing scaffolding.
- Identity and signing scaffolding.
- Consumer and admin portal routes.
- Second Life and licensing foundations.
- Audit records.
- A sandbox worker registered in Aspire with browser execution disabled.
- A branded HIP Control admin interface.

## 2.3 Known gaps that must not be hidden

The current repository is an MVP foundation. It is not production-ready. The highest-value gaps are:

- Production authentication and authorization.
- Removal of development-only identity bypass risks.
- Secure secret and encryption-key management.
- Durable queues and outbox processing.
- Redis-backed distributed dedupe and rate limiting.
- Database migrations and production startup safety.
- Production cryptographic key lifecycle.
- Signed HIP envelopes and trust receipts.
- Hardened provider workers and provider result normalization.
- Hardened browser sandbox execution.
- Full rule approval, versioning, and rollback.
- Stronger anti-poisoning controls for public feedback and scans.
- Production deployment, backup, restore, and incident procedures.

# 3. Product Vision

## 3.1 Product statement

HIP is an open protocol and product platform that adds a trust layer above existing internet transport. It should give clear, explainable answers without forcing users to understand certificates, threat feeds, cryptographic algorithms, or raw security logs.

The normal experience should be quiet. Routine trust details belong in a browser popup or portal. A page banner should appear only when there is a meaningful concern.

## 3.2 Core principles

1. Trust must be earned.
2. Risk must be supported by evidence.
3. Unknown must remain unknown.
4. No bad signal found does not mean trusted.
5. HTTPS does not mean trusted.
6. A valid signature proves origin and integrity, not safety.
7. Domain trust must not automatically transfer to every page, download, or user-generated item.
8. HIP must explain the result in plain language.
9. Private content must stay private by default.
10. AI can assist. It cannot become the final authority.
11. Security controls must be useful without becoming constantly annoying.
12. Clients are replaceable. The protocol and trust model are the product.

## 3.3 Primary users

| User | Main need |
|---|---|
| Everyday consumer | Understand whether a site, link, file, or message looks safe |
| Verified site owner | Prove control of a domain and display a live HIP badge |
| Organization administrator | Manage identities, policies, devices, providers, and risk rules |
| Trust reviewer | Review reports, appeals, rule changes, and reputation overrides |
| Browser extension user | Receive automatic, low-noise website protection |
| Second Life user | Check suspicious links and receive private risk warnings |
| Developer or platform | Call HIP APIs and verify signed trust receipts |

# 4. Scope

## 4.1 MVP scope

The production MVP includes:

- Domain and exact-page trust lookup.
- Privacy-safe browser page signal collection.
- Layered domain, page, content-risk, and final HIP scoring.
- Explainable reasons, warnings, and confidence.
- Public lookup, safety page, and live trust badge.
- Website ownership verification by DNS TXT and `.well-known/hip.json`.
- Browser extension for Chrome and Edge first.
- Consumer portal.
- Admin portal.
- Weighted feedback, reports, reviews, appeals, and reputation overrides.
- JSON rule builder, simulation, approval, versioning, and rollback.
- Identity, key, signature, nonce, replay, and trust-receipt foundations.
- CoreDNS local test environment.
- Second Life HUD MVP after browser and protocol foundations are stable.
- PostgreSQL persistence, Redis caching, and durable background work.
- Strong auditing, privacy controls, observability, and rate limiting.

## 4.2 Later scope

Later clients and capabilities include:

- Email clients and gateways.
- Chat and social platform adapters.
- File and image verification tools.
- Signed media and delegated likeness permissions.
- Enterprise trust-aware DNS resolver.
- Platform SDKs.
- Hardware-backed key storage.
- Federation between HIP operators.
- Optional blockchain anchoring for key revocation or reputation snapshots only.

## 4.3 Explicit non-goals for the MVP

- HIP is not a replacement for TLS, DNS, antivirus, EDR, or browser security.
- HIP will not store full private chat histories by default.
- HIP will not claim that every verified domain is safe.
- HIP will not use blockchain for normal messages, scan logs, receipts, or lookups.
- HIP will not let AI directly activate high-impact rules.
- HIP will not auto-block ordinary unknown sites with no strong risk evidence.
- HIP will not turn into many independent microservices before scale requires it.

# 5. Architecture

## 5.1 Architectural style

HIP should remain a modular monolith for the production MVP. The code must keep strong module boundaries so high-load or sensitive modules can become separate services later.

Use internal application events now. Add a durable outbox before production. Extract services only when there is a measured reason, such as separate scaling, isolation, ownership, or regulatory needs.

## 5.2 Layer responsibilities

### HIP.Domain

Contains pure business concepts:

- HIP protocol envelope and receipt models.
- Identity, key, rotation, and revocation models.
- Domain, page, content, and final score primitives.
- Evidence, reason, warning, and confidence models.
- Reputation subjects and feedback events.
- Rule definitions, versions, modes, approvals, and simulations.
- Reports, reviews, appeals, and audit event contracts.
- Device, license, and platform trust concepts.

Domain code must not depend on ASP.NET Core, Entity Framework Core, Redis, HTTP clients, or UI types.

### HIP.Application

Contains use cases and contracts:

- Commands and queries.
- Validators.
- Scoring orchestration.
- Evidence normalization.
- Rule evaluation and simulation.
- Identity and signing use cases.
- Browser, consumer, admin, public lookup, and Second Life facades.
- Authorization decisions that are independent of transport.
- Interfaces for persistence, queues, clocks, crypto, DNS, providers, and audit.

### HIP.Infrastructure

Contains adapters:

- PostgreSQL repositories and Entity Framework Core mappings.
- Redis cache, dedupe, rate-limit, nonce, and distributed lock adapters.
- DNS and `.well-known` verification clients.
- External evidence providers.
- Cryptographic provider implementations.
- Outbox and background job persistence.
- Secret-store and key-store adapters.
- Audit persistence.

### HIP.ApiService

Contains public and client API hosting:

- Versioned public APIs.
- Browser extension APIs.
- Domain verification APIs.
- Site-safety APIs.
- Authentication for API clients.
- Rate limiting, CORS, compression, caching, health, and OpenAPI.

### HIP.Web

Contains:

- Public lookup and safety pages.
- Consumer portal.
- Admin portal.
- Interactive rule builder and JSON view.
- Review and appeal workflows.
- Live operational dashboards.

### HIP.SandboxWorker

Contains isolated slow or risky work:

- Browser rendering and dynamic page analysis.
- External provider calls that exceed the fast-path budget.
- File and URL detonation in a later phase.
- Strict job timeout, memory, CPU, network, and output limits.

### HIP.AppHost

Contains local orchestration only:

- API, web, worker, PostgreSQL, Redis, and CoreDNS resources.
- References, health dependencies, and local configuration.
- No production secrets or hard-coded encryption keys.

### HIP.ServiceDefaults

Contains:

- OpenTelemetry.
- Health checks.
- Service discovery.
- Standard resilience configuration.
- Shared logging and correlation behavior.

## 5.3 Future service boundaries

The following modules may be extracted later without changing their public contracts:

1. Identity Service.
2. Device Trust Service.
3. Policy and Rules Service.
4. Reputation Service.
5. Messaging and Content Security Service.
6. Security Event and Audit Service.
7. Risk and Scoring Service.

# 6. HIP Protocol Specification

## 6.1 Protocol goals

The protocol must support signed claims and verification results for:

- Websites and domains.
- Exact URLs.
- Files and downloads.
- Images and media.
- Emails and messages.
- Apps and API responses.
- Devices and organizations.

## 6.2 Versioning

- Protocol version format: semantic major and minor, such as `1.0`.
- Every envelope, receipt, key record, rule document, and public API response must include a schema or protocol version.
- Unknown major versions must be rejected.
- Unknown optional fields in the same major version should be ignored unless marked critical.
- Breaking changes require a new major version and parallel support during migration.

## 6.3 Canonical signing

Use RFC 8785 JSON Canonicalization Scheme for JSON that is signed.

Signing steps:

1. Validate the payload schema.
2. Remove the signature value from the canonical signing object.
3. Canonicalize JSON using RFC 8785.
4. Hash or sign according to the selected algorithm profile.
5. Store algorithm, key ID, context, signature, and canonicalization version.
6. Verify expiry, issuer, key state, signature, and replay state before accepting claims.

## 6.4 HIP envelope

Minimum envelope shape:

```json
{
  "hipVersion": "1.0",
  "messageId": "0190f1b0-6d5e-7e4a-8e57-46ef7c76450f",
  "issuedAtUtc": "2026-07-12T18:00:00Z",
  "expiresAtUtc": "2026-07-12T18:05:00Z",
  "nonce": "base64url-random-value",
  "issuer": {
    "identityId": "hip:org:example",
    "keyId": "key-2026-01"
  },
  "subject": {
    "type": "website",
    "id": "https://example.com/"
  },
  "content": {
    "mediaType": "application/json",
    "hashAlgorithm": "SHA-256",
    "digest": "base64url-digest"
  },
  "claims": {
    "originVerified": true,
    "verificationMethod": "dns-txt"
  },
  "signature": {
    "algorithm": "ML-DSA-65",
    "canonicalization": "RFC8785",
    "value": "base64url-signature"
  }
}
```

## 6.5 Trust receipt

A HIP trust receipt records what HIP evaluated. It must be signed separately from the original content.

Required fields:

- Receipt ID.
- Related message or scan ID.
- Subject type and normalized subject ID.
- Evaluation time and expiry.
- Domain trust score.
- Page trust score when relevant.
- Content risk score when relevant.
- Final HIP score.
- Status and confidence.
- Reason and warning codes.
- Policy version and rule-set version.
- Evidence digest, not private raw evidence.
- HIP signer identity, key ID, and signature.

Receipts must not expose raw page text, passwords, form values, tokens, cookies, private messages, or unrelated browsing history.

## 6.6 Replay defense

- Every signed request that changes state must include a unique nonce and timestamp.
- Default timestamp tolerance: 5 minutes, configurable by client type.
- Nonces must be stored in Redis with a TTL at least as long as the acceptance window.
- Duplicate message IDs or nonces must fail with a clear replay error.
- Redis failure behavior must be explicit. High-impact signed operations fail closed when replay state cannot be checked.
- Read-only public lookup can remain available in degraded mode.

## 6.7 Cryptographic policy

Production signing target:

- ML-DSA-65 under NIST FIPS 204.
- Use the .NET `MLDsa` base abstraction where supported.
- Detect platform support at startup.
- Production signing must fail closed when the required provider is unavailable.
- Ed25519 may be retained only for legacy compatibility, local test fixtures, or an explicit hybrid transition profile. It must never be labeled quantum-resistant.
- Cryptographic algorithms must remain behind interfaces and a provider factory.
- Never create a custom cryptographic algorithm.

Suggested interfaces:

```csharp
public interface IHipSignatureProvider
{
    string AlgorithmId { get; }
    bool IsSupported { get; }
    ValueTask<HipSignatureResult> SignAsync(
        ReadOnlyMemory<byte> canonicalPayload,
        HipKeyReference key,
        CancellationToken cancellationToken);
    ValueTask<HipVerificationResult> VerifyAsync(
        ReadOnlyMemory<byte> canonicalPayload,
        HipSignature signature,
        CancellationToken cancellationToken);
}
```

## 6.8 Key lifecycle

Key states:

- Pending.
- Active.
- Rotating.
- Retired.
- Revoked.
- Destroyed.

Requirements:

- Private keys must be encrypted at rest or stored in a managed key service.
- Private key material must never be returned by a normal API.
- Rotation must overlap old and new public keys for a defined period.
- Revocation records must be signed and auditable.
- A revoked key cannot sign new data.
- Historical signatures may remain valid only when the receipt proves the signature was created before revocation and policy allows it.
- Key export must be disabled by default.

# 7. Identity and Trust Subjects

## 7.1 Identity types

- Anonymous installation.
- Consumer account.
- Site owner.
- Organization.
- Administrator.
- Service account.
- Device.
- Application.
- Platform account.

## 7.2 Identity confidence

Identity confidence is separate from safety score. Suggested levels:

- Anonymous.
- Observed.
- Verified.
- Strongly verified.
- Administratively trusted.

Verification evidence can include:

- Email verification.
- MFA.
- Domain control.
- Device registration.
- Signed challenge response.
- Organization approval.
- Platform account proof.

## 7.3 Device registration

Device records should contain:

- Device ID.
- Owner identity ID.
- Public key or key reference.
- Friendly name.
- Platform type.
- First seen and last seen.
- Trust state.
- Revocation state.
- Privacy-safe device metadata.

Do not store invasive hardware fingerprints. Use a generated device identity and signed challenge.

# 8. Website Verification

## 8.1 DNS TXT verification

Record name:

```text
_hip.example.com
```

Record value:

```text
hip-site-verification=v1:<random-token>
```

Rules:

- Tokens must be random, time-limited, single-purpose, and hashed at rest.
- Verification proves domain control only.
- Verification must not automatically assign a trusted safety status.
- Recheck domain control on a schedule.
- Expire verification after repeated failures or ownership changes.

## 8.2 Well-known verification

URL:

```text
https://example.com/.well-known/hip.json
```

Minimum fields:

- HIP schema version.
- Domain.
- Identity ID.
- Public key references.
- Verification challenge.
- Optional policy and contact references.
- Signature.

## 8.3 Local CoreDNS lab

The current local lab should remain available through Aspire.

Required test cases:

- Valid TXT record.
- Missing TXT record.
- Wrong token.
- Multiple TXT records.
- Expired verification.
- DNS timeout.
- TCP-only local query.
- Unicode and punycode domain handling.
- Subdomain versus registrable-domain handling.

CoreDNS is a local verification and future enterprise resolver tool. It is not the main HIP application and should not replace normal public DNS in the MVP.

# 9. Evidence Collection

## 9.1 Evidence categories

- Domain evidence.
- Exact-page evidence.
- Content and behavior evidence.
- Identity evidence.
- Reputation evidence.
- Device and key evidence.
- Organization evidence.
- External provider evidence.
- Rule and policy evidence.

## 9.2 Privacy-safe browser signals

Allowed examples:

- Domain and normalized URL.
- URL hash.
- Redirect count and normalized redirect domains.
- HTTPS present.
- Login form present.
- Password field present.
- Payment field present.
- Form target domain relationship.
- Inline script count.
- External script domain list or hashed list.
- Suspicious script-pattern count.
- Link counts.
- Shortened-link count.
- Obfuscated-link count.
- Executable download-link count.
- Archive download-link count.
- Matched risk labels.
- Page category and user-generated-content flag.

Forbidden browser collection:

- Passwords.
- Typed form values.
- Cookies.
- Authentication tokens.
- Full page body text.
- Private messages.
- Unrelated browsing history.
- Personal document contents.

## 9.3 Provider abstraction

Each external provider adapter must return a normalized result:

```text
ProviderName
ProviderVersion
CheckedAtUtc
Status: Success | Timeout | Unavailable | Error | Disabled
ThreatSignals[]
TrustSignals[]
Confidence
LatencyMs
CacheUntilUtc
PrivacyClassification
RawReferenceHash
```

Planned adapters:

- TLS and SSL Labs-style evidence.
- Google Web Risk-style threat evidence.
- VirusTotal-style threat evidence.
- DNS age and registration evidence.
- Safe browsing or malware feeds.
- HIP internal reputation.

Provider rules:

- A provider hit is evidence, not the entire HIP decision.
- A clean result does not create trust for an unknown target.
- Timeouts must lower confidence, not crash scoring.
- Conflicting results must be surfaced.
- External calls must use strict timeouts, retries only when safe, circuit breakers, caching, and concurrency limits.
- Slow providers run outside the public fast path.

# 10. Scoring Model

## 10.1 Score layers

Every user-facing result must expose:

- `DomainTrustScore` from 0 to 100.
- `PageTrustScore` from 0 to 100 when a page exists.
- `ContentRiskScore` from 0 to 100, where higher means more risk.
- `FinalHipScore` from 0 to 100, where higher means more trust.
- Status.
- Confidence level.
- Reasons.
- Warnings.
- Evidence freshness.

## 10.2 Status bands

| Final score | Status |
|---:|---|
| 0-9 | Dangerous |
| 10-24 | High Risk |
| 25-39 | Suspicious |
| 40-49 | Unknown |
| 50-69 | Limited Trust Data |
| 70-84 | Mostly Trusted |
| 85-100 | Trusted |

## 10.3 Baseline formula

Recommended starting formula:

```text
BaseSafety =
    (DomainTrustScore * 0.35) +
    (PageTrustScore * 0.30) +
    ((100 - ContentRiskScore) * 0.35)

FinalHipScore = clamp(round(BaseSafety + Adjustments), 0, 100)
```

The formula is not enough by itself. Apply evidence rules and caps after calculation.

## 10.4 Mandatory caps and overrides

- Confirmed malware or phishing evidence: final score must be 0-9.
- Strong executable-download risk with weak identity: cap final score at 39.
- Unknown target with little evidence: cap final score at 69.
- HTTPS alone: small positive signal only, no more than 3 points.
- Valid domain verification: improves origin confidence, not more than a modest trust adjustment by itself.
- Valid signature: improves origin and integrity confidence, not automatic safety.
- Trusted parent domain with risky exact page: page and content layers must lower the final result.
- User-generated areas must not inherit the full parent-domain page score.
- Conflicting evidence lowers confidence and adds a review warning.
- Disabled, watch-only, or unapproved rules cannot change the final score.

## 10.5 Confidence

Suggested confidence levels:

- Low.
- Medium.
- High.
- Conflicted.

Confidence should consider:

- Evidence count.
- Evidence quality.
- Evidence freshness.
- Provider agreement.
- Identity strength.
- Rule coverage.
- Missing or timed-out checks.

Confidence must not be encoded inside the final trust score. A score of 70 with low confidence is not the same as 70 with high confidence.

## 10.6 Explainability

Every score-changing signal must have:

- Stable reason code.
- Plain-language explanation.
- Score impact.
- Evidence source.
- Evidence time.
- Privacy classification.

Example:

```text
The parent domain has strong public trust signals. This page contains an executable download and has limited page history, so the exact page needs extra care.
```

# 11. Reputation and Feedback

## 11.1 Reputation subjects

- User or sender.
- Domain.
- Exact page.
- Device or key.
- Organization.
- Application.
- Content pattern.
- Platform account.

## 11.2 Feedback options

Browser users should see simple actions:

- Looks Safe.
- Looks Suspicious.

Admin and review tools may use more detailed categories.

## 11.3 Default feedback weights

Suggested configurable defaults:

| Reporter level | Weight |
|---|---:|
| Anonymous | 0.25 |
| Verified | 1.00 |
| Trusted | 2.00 |
| Admin or approved reviewer | 4.00 |

Controls:

- Per-device and per-account submission limits.
- Duplicate suppression.
- Time decay.
- Diversity checks across reporters and networks.
- New-account limits.
- Coordinated-report detection.
- A large number of weak reports cannot instantly create a Dangerous result.
- High-impact reputation changes require supporting evidence or review.

# 12. Rules, Simulation, and Self-Healing

## 12.1 Rule format

Rules are JSON-first. The normal admin UI is a simple form with the JSON shown underneath. Advanced users can edit raw JSON after validation.

Required fields:

- Rule ID.
- Schema version.
- Name and description.
- Status.
- Mode: disabled, watch, active.
- Severity and impact level.
- Conditions.
- Actions.
- Creator type: human, imported, AI-suggested.
- Simulation requirement.
- Approval requirement.
- Version and prior version.
- Effective and expiry times.
- Rollback information.

## 12.2 Supported MVP operators

- equals.
- notEquals.
- lessThan.
- greaterThan.
- contains.
- startsWith.
- endsWith.
- in.
- notIn.
- exists.

Every operator must be type-safe. Unsupported fields and operators must be rejected.

## 12.3 Supported MVP actions

- Add reason.
- Add warning.
- Adjust one score within a bounded range.
- Set risk level.
- Require review.
- Route to safety page.
- Allow.
- Block.

High-impact actions must be tightly controlled.

## 12.4 Simulation requirements

Every generated or changed rule must run simulation before activation.

Simulation cases must include:

- Known-safe targets.
- Known-risk targets.
- Unknown clean targets.
- Shortened links.
- Obfuscated links.
- Broken-up links.
- Login and payment forms.
- Executable downloads.
- Archive downloads.
- User-generated pages.
- Conflicting provider results.
- Provider timeouts.
- Privacy-safe chat, email, file, and image metadata fixtures.

Simulation output:

- Pass or fail.
- Detection rate.
- False-positive rate.
- False-negative rate.
- Performance impact.
- Privacy impact.
- Confidence.
- Failed cases.
- Recommended mode.
- Recommended action.
- Rollback plan.

## 12.5 Approval policy

| Rule impact | Activation policy |
|---|---|
| Low | May auto-activate only after strong simulation results and bounded score impact |
| Medium | Requires one authorized approver |
| High | Starts in watch mode and requires two-person approval |
| Critical | Manual deployment only, two-person approval, explicit rollback test |

Actions that block, force Dangerous status, revoke identities, or create major reputation overrides are always High or Critical.

## 12.6 Rollback

- Every active rule must point to a prior version or known disabled state.
- Rollback must be one controlled action.
- Automatic rollback can be added later after reliable false-positive monitoring.
- The audit record must show who approved, activated, rolled back, and why.

## 12.7 AI-assisted rules

AI may suggest a rule. It cannot approve or activate it.

AI output must include:

- Proposed structured conditions.
- Proposed actions.
- Reasoning summary.
- Expected risk reduction.
- Expected false-positive risk.
- Required simulation set.

# 13. Browser Extension

## 13.1 Platforms

- Chrome and Microsoft Edge first using Manifest V3.
- Firefox after the core flow is stable.

## 13.2 Normal experience

- Toolbar shield shows current status.
- Popup shows score layers, confidence, reasons, warnings, and evidence freshness.
- The injected banner appears only for meaningful warnings or high-risk results.
- Routine safe or limited-data results stay in the popup.
- Users can open the public safety page for more detail.

## 13.3 Automatic scan flow

1. Confirm the page is eligible and public.
2. Normalize the URL.
3. Check local cache.
4. Collect privacy-safe page signals.
5. Request a fast HIP score.
6. Save a privacy-safe scan summary.
7. Update toolbar icon and popup.
8. Show a banner only when policy requires it.
9. Queue a slower provider or sandbox scan when needed.
10. Refresh the result when the slower scan completes.

## 13.4 Extension security

- Restrict host permissions to the minimum practical set.
- Do not inject on browser internal pages, extension stores, local files, or sensitive protected pages unless explicitly supported.
- Validate every message between content scripts, service worker, popup, and API.
- Treat page DOM data as hostile.
- Use strict Content Security Policy.
- Do not use remote executable code.
- Do not store secrets in extension storage.
- Use a generated installation ID and optional device key.
- Sign high-trust client submissions in a later phase.

## 13.5 Extension controls

- Protection enabled.
- Banner enabled.
- Only warn for High Risk and Dangerous.
- Scan downloads.
- Send anonymous feedback.
- Privacy mode.
- API environment for local development only.

# 14. Public Experience

## 14.1 Public lookup

Public lookup should show:

- Domain.
- Verification status.
- Domain trust score.
- Latest public-safe page information when a URL is supplied.
- Final score and confidence.
- Plain reasons and warnings.
- Evidence freshness.
- Report and appeal options.
- Clear statement that HIP is guidance, not a guarantee.

## 14.2 Safety page

The safety page is used for risky links and manual checks.

It should:

- Explain why the user was sent there.
- Show the exact target safely without making it clickable by default for dangerous results.
- Separate domain trust from page and content risk.
- Offer Go Back.
- Offer Continue only when policy permits.
- Require an extra confirmation for dangerous results.
- Record the decision without storing private browsing data.

## 14.3 Live badge

The live badge must:

- Use current HIP data.
- Never be a static image that a site can fake as current.
- Link to the HIP public lookup page.
- Show verification separately from safety status.
- Use a signed badge payload or signed trust receipt.
- Support cache control and revocation.
- Fail safely when HIP cannot be reached.

# 15. Consumer Portal

Route root: `/consumer`

Required pages:

- Overview and protection status.
- Scan history.
- Report history.
- Appeal status.
- Alert settings.
- Devices.
- Licenses.
- Account security.

Consumer rules:

- Show only data owned by the signed-in user.
- Use pagination.
- Allow privacy-safe export and account deletion requests.
- Explain retention.
- Do not expose internal reviewer notes or private provider data.

# 16. Admin Portal

Route root: `/admin`

Required areas:

- Live dashboard.
- Scan results.
- Threat and safety findings.
- Review queue.
- Reports.
- Appeals.
- Reputation and overrides.
- Rules and simulations.
- Self-healing suggestions.
- Identities and keys.
- Domain verifications.
- Devices and licenses.
- External providers.
- Platform connections.
- Audit logs.
- System health and diagnostics.

## 16.1 Admin dashboard rules

- Cards must use stored live counts.
- No placeholder incidents or fake trends.
- A disconnected data source must show Not Connected.
- Empty data must show No Data Yet.
- Every card should link to its detailed page.
- Use the approved HIP brand system.
- Preserve the original logo and icon set.
- Preserve the left-side status accent lines on cards where they are part of the design system.

## 16.2 Roles

Suggested roles:

- Owner.
- Administrator.
- Security Reviewer.
- Trust Analyst.
- Support.
- Site Owner.
- Consumer.

Use policy-based authorization. Do not check role names directly inside business logic.

## 16.3 Production authentication

- Replace development-only header identity with real authentication.
- Use ASP.NET Core Identity or an OIDC-compatible abstraction.
- Use secure cookies for the Blazor UI.
- Use JWT or signed client credentials for APIs that require identity.
- Require MFA for Owner and Administrator.
- Require recent reauthentication for key changes, critical rules, role changes, and reputation overrides.
- Development authentication must be explicit, disabled by default outside Development, and limited to loopback.

# 17. Second Life HUD

The Second Life HUD is a HIP client, not the HIP core.

## 17.1 MVP experience

- Works without a web login for basic use.
- Uses a setup code or license key.
- Checks links the HUD is permitted to receive through Second Life scripting capabilities.
- Low risk: HUD-only status.
- Medium risk: private warning.
- High risk: private warning and optional popup.
- User can open a HIP safety page for details.
- Marketplace demo mode is supported.

## 17.2 Privacy

- Do not send full group or private chat logs.
- Send only the risky URL, platform, timestamp, sender hash when needed, and matched risk reason.
- Make the limitation of Second Life scripting permissions clear. Do not claim universal chat interception when the platform does not provide it.

# 18. AI Policy

## 18.1 Allowed AI uses

- Detect scam wording, urgency, impersonation, and social-engineering labels from approved privacy-safe inputs.
- Suggest risk explanations.
- Suggest rules.
- Cluster repeated anonymized patterns.
- Assist reviewers.

## 18.2 Forbidden AI uses

- Final authorization decisions.
- Direct activation of high-impact rules.
- Raw private chat analysis by default.
- Processing passwords, tokens, cookies, or typed form values.
- Inventing evidence.
- Marking a target trusted because the model sounds confident.

## 18.3 Provider design

- AI must be behind an interface.
- AI can be disabled without breaking core HIP functions.
- Store model name, prompt version, input classification, output hash, latency, and reviewer outcome.
- Redact inputs before sending them to any remote provider.
- Support a local provider later.

# 19. Persistence Model

## 19.1 Core tables or aggregates

- `Identities`
- `IdentityVerifications`
- `Keys`
- `KeyRevocations`
- `Devices`
- `DomainVerifications`
- `ScanRequests`
- `ScanResults`
- `EvidenceItems`
- `ProviderObservations`
- `TrustReceipts`
- `ReputationSubjects`
- `FeedbackEvents`
- `Reports`
- `ReviewItems`
- `Appeals`
- `ReputationOverrides`
- `RuleDefinitions`
- `RuleVersions`
- `RuleSimulations`
- `RuleApprovals`
- `Licenses`
- `PlatformConnections`
- `SandboxJobs`
- `AuditEntries`
- `OutboxEvents`

## 19.2 Database rules

- Use PostgreSQL in normal development and production.
- SQLite and in-memory stores are for explicit tests only.
- Use migrations. Do not use `EnsureCreated` as the production schema strategy.
- Add optimistic concurrency to mutable reviewed records.
- Use UTC timestamps.
- Use normalized registrable-domain and exact-URL keys.
- Encrypt sensitive columns.
- Hash tokens and privacy identifiers.
- Keep large provider payloads out of hot tables.
- Add indexes for current status, subject, domain, created time, review state, and rule version.
- Use soft deletion only when retention or audit needs it. Do not hide deleted state from audit.

# 20. API Plan

## 20.1 Existing public and browser routes to preserve

- `GET /api/v1/public/lookup/domain/{domain}`
- `GET /api/v1/public/badge/domain/{domain}`
- `POST /api/v1/public/feedback`
- `POST /api/v1/domain-verification/check`
- `POST /api/v1/browser/score-site`
- `POST /api/v1/browser/scan-links`
- `POST /api/v1/browser/scan-results`
- `GET /api/v1/browser/scan-results/{domain}`
- Site-safety routes already present in the repository.

## 20.2 Planned protocol and identity routes

```text
POST /api/v1/protocol/verify-envelope
POST /api/v1/protocol/issue-receipt
GET  /api/v1/protocol/receipts/{receiptId}
POST /api/v1/identity/challenges
POST /api/v1/identity/challenges/{id}/verify
GET  /api/v1/identities/{identityId}/keys
POST /api/v1/identities/{identityId}/keys/rotate
POST /api/v1/identities/{identityId}/keys/{keyId}/revoke
```

## 20.3 Planned domain routes

```text
POST /api/v1/domains/verifications
POST /api/v1/domains/verifications/{id}/check
GET  /api/v1/domains/{domain}/verification
POST /api/v1/domains/{domain}/revoke-verification
```

## 20.4 Planned authenticated client routes

```text
POST /api/v1/clients/register
POST /api/v1/clients/challenge
POST /api/v1/clients/challenge/verify
POST /api/v1/browser/signed-scan-results
```

## 20.5 API response rules

- Use stable error codes.
- Include correlation ID.
- Use Problem Details for errors.
- Do not return stack traces.
- Paginate lists.
- Use ETags for suitable public reads.
- Add idempotency keys for state-changing client operations.
- Sign high-value public trust results after the protocol signing foundation is ready.

# 21. Security Requirements

## 21.1 Main threats

- Data poisoning through public scans and feedback.
- Replay attacks.
- Stolen or forged client identity.
- Key compromise.
- Malicious or mistaken admin rules.
- SSRF through URL and provider scanning.
- XSS and unsafe HTML rendering.
- SQL or command injection.
- DNS rebinding.
- Sandbox escape.
- Provider compromise or misleading provider data.
- Credential stuffing and account takeover.
- Session theft.
- Abuse of development authentication.
- Denial of service.
- Privacy leakage through logs or evidence.

## 21.2 Required controls

- MFA for privileged roles.
- Brute-force protection.
- Suspicious IP and device challenge.
- Session rotation after login and privilege changes.
- Secure, HttpOnly, SameSite cookies.
- CSRF protection for browser state changes.
- Strict CORS allowlists.
- Per-client, per-account, per-device, per-domain, and per-IP rate limits.
- Distributed dedupe in Redis.
- Signed high-trust client requests.
- Nonce and replay protection.
- URL normalization and SSRF protection.
- Block private, loopback, link-local, metadata, and reserved network targets in public scanners.
- Re-resolve DNS and verify the connected IP.
- Output encoding and no unsafe raw HTML.
- Content Security Policy.
- Parameterized database access through EF Core.
- Secret scanning and dependency vulnerability scanning in CI.
- Two-person approval for critical rules and overrides.
- Immutable or append-only audit behavior for critical actions.
- Backup and restore tests.

## 21.3 Local-development secret fix

The current AppHost contains local encryption and hashing key constants. Replace these with:

- .NET user secrets for local development.
- Environment variables for CI.
- Managed secrets for production.
- Startup validation that rejects known default or example values outside Development.

# 22. Privacy and Retention

## 22.1 Data minimization

Store only what is needed to explain and improve trust decisions.

Default report fields:

- Risky URL or normalized target.
- Domain.
- URL hash.
- Sender hash only when needed.
- Platform.
- Risk reason.
- Timestamp.
- HIP signature or receipt reference.

## 22.2 Suggested retention defaults

| Data | Default retention |
|---|---|
| Normal privacy-safe scan summaries | 90 days |
| Provider raw response references | 7-30 days, then retain normalized evidence only |
| Confirmed dangerous patterns | Long-term with periodic review |
| Anonymous feedback events | 90 days unless part of a reviewed case |
| User-linked data | Minimum needed; user deletion workflow required |
| Security audit records | 1 year minimum, configurable |
| Nonces and dedupe keys | Minutes or hours based on replay window |
| Sandbox temporary files | Delete immediately after result extraction |

## 22.3 Privacy rights

- Data export.
- Account deletion request.
- Device revocation.
- Feedback correction or appeal.
- Clear retention notice.
- Clear distinction between public and private data.

# 23. Performance and Reliability

## 23.1 Initial targets

| Operation | Target |
|---|---:|
| Cached public domain lookup p95 | Under 150 ms |
| Database-backed public lookup p95 | Under 500 ms |
| Browser fast score p95 | Under 750 ms |
| Browser popup from cache | Under 300 ms |
| Public scan acceptance | Under 250 ms before slow work |
| Slow provider or sandbox job | Async, normally under 30 seconds |
| Admin paged list p95 | Under 750 ms |

## 23.2 Reliability behavior

- Public lookup remains available when optional providers are down.
- Provider timeouts lower confidence.
- High-impact signed actions fail closed when identity, nonce, or key verification is unavailable.
- Cache failures fall back to PostgreSQL when safe.
- Queue failures must not silently lose accepted work. Use outbox and retry.
- Health checks must separate liveness, readiness, and dependency health.

# 24. Observability

Required telemetry:

- Correlation ID and trace ID.
- Request count, latency, error rate, and status code.
- Cache hit rate.
- Rate-limit rejection count.
- Provider latency, timeout, and circuit state.
- Queue depth and job age.
- Rule match count and false-positive reports.
- Score distribution and confidence distribution.
- Database latency and migration version.
- Authentication failures and privileged actions.
- Sandbox job timeout and resource limits.

Logging rules:

- Structured logs.
- No secrets.
- No raw private page or message content.
- Hash or truncate sensitive identifiers.
- Security events include actor, action, target, outcome, and correlation ID.

# 25. Testing Strategy

## 25.1 Required test layers

- Unit tests for every new method and domain behavior.
- Architecture tests for layer dependencies.
- Integration tests with PostgreSQL.
- Integration tests with Redis.
- CoreDNS integration tests.
- API contract tests.
- Authentication and authorization tests.
- Cryptographic known-answer and failure tests.
- Rule simulation regression tests.
- Scoring accuracy regression tests.
- Browser extension unit and message-contract tests.
- Playwright end-to-end tests for public, consumer, and admin flows.
- Migration tests.
- Load and rate-limit tests.
- Security tests for replay, SSRF, injection, XSS, CSRF, and authorization bypass.
- Backup and restore tests before production.

## 25.2 Mandatory scoring scenarios

- Trusted domain homepage.
- Trusted domain user-generated page.
- Unknown clean HTTPS site.
- Unknown login page.
- Unknown payment page.
- Executable download.
- Archive download.
- Shortened URL.
- Obfuscated URL.
- Known phishing hit.
- Known malware hit.
- Provider timeout.
- Conflicting providers.
- Verified signature with risky content.
- Many anonymous reports.
- Trusted reviewer report.
- Disabled rule.
- Watch rule.
- Approved active rule.
- Critical override with and without approval.

## 25.3 Definition of done for a method or feature

A work item is not done until:

- Input validation exists.
- Authorization is correct.
- Security and privacy behavior is documented.
- Logging is safe.
- Cancellation is supported for I/O.
- Tests cover success, validation failure, authorization failure, and important edge cases.
- No secrets are added.
- Targeted tests pass.
- Full build passes.
- Relevant docs are updated.

# 26. Deployment and Operations

## 26.1 Environments

- Local Development.
- CI Test.
- Staging.
- Production.

Each environment must have separate databases, Redis instances, keys, provider credentials, and callback URLs.

## 26.2 Deployment direction

- Build OCI container images for HIP.ApiService, HIP.Web, and HIP.SandboxWorker.
- Use Aspire publishing or generated deployment artifacts as a starting point.
- Use a managed PostgreSQL service in production when possible.
- Use managed Redis when possible.
- Put public traffic behind a reverse proxy or managed ingress.
- Enforce TLS at the edge and application.
- Use a managed secret store.
- Run database migrations as a controlled deployment step.
- Do not allow automatic destructive schema changes on startup.

## 26.3 Backups

- Automated PostgreSQL backups.
- Point-in-time recovery where available.
- Encrypted key and configuration backup under separate access controls.
- Regular restore drills.
- Audit the restore operation.

# 27. Implementation Roadmap

## Phase 0 - Repository truth and immediate hardening

Goal: make the current foundation safe to continue.

Work packages:

1. Create a current feature and gap inventory from the repository.
2. Remove hard-coded local encryption and hashing keys from AppHost.
3. Lock development authentication to explicit Development and loopback conditions.
4. Add startup rejection for unsafe production defaults.
5. Replace production `EnsureCreated` behavior with migrations and safe startup checks.
6. Add distributed Redis dedupe and nonce interfaces while preserving test adapters.
7. Update Aspire from 13.4.2 to the latest tested 13.4 patch.
8. Add baseline dependency and secret scanning in CI.
9. Confirm all admin cards use real data or no-data states.
10. Preserve brand asset hash tests.

Exit criteria:

- Full solution builds and tests.
- Aspire starts API, web, worker, PostgreSQL, Redis, and CoreDNS.
- No source-controlled keys.
- Development auth cannot work in Production.
- Database migration path is documented and tested.

## Phase 1 - Protocol and cryptographic foundation

1. Add versioned HIP envelope models.
2. Add RFC 8785 canonicalization service.
3. Add signature provider strategy and factory.
4. Add ML-DSA-65 provider with platform support checks.
5. Add key lifecycle and revocation models.
6. Add nonce and replay store.
7. Add envelope verification use case.
8. Add signed trust receipt model and service.
9. Add known-answer, tampering, expiry, nonce, and revocation tests.
10. Add protocol documentation and example fixtures.

Exit criteria:

- A valid envelope verifies.
- Any changed signed field fails verification.
- Expired, replayed, unknown-version, and revoked-key envelopes fail correctly.
- HIP can issue and verify a trust receipt.

## Phase 2 - Production identity and client trust

1. Add real user authentication.
2. Add MFA for privileged roles.
3. Add policy-based authorization tests for every admin route.
4. Add device registration and signed challenge.
5. Add browser installation registration.
6. Add API client credentials and scoped permissions.
7. Add recent-reauthentication checks for critical actions.
8. Add session and account-takeover protections.

## Phase 3 - Scoring and evidence productionization

1. Formalize score pipeline interfaces.
2. Normalize all evidence sources.
3. Apply caps and overrides.
4. Separate confidence from score.
5. Add reason-code catalog.
6. Add evidence freshness.
7. Add full scoring regression suite.
8. Add signed trust results after scoring.
9. Add slow-path provider jobs.

## Phase 4 - Rules, simulations, approvals, and rollback

1. Version rule schema.
2. Add typed field catalog.
3. Add rule version storage.
4. Add simulation result persistence.
5. Add approval records.
6. Add two-person approval for high-impact rules.
7. Add one-click rollback.
8. Add false-positive monitoring.
9. Keep AI suggestions in draft only.

## Phase 5 - Browser extension production MVP

1. Harden Manifest V3 permissions and CSP.
2. Add client registration and optional request signing.
3. Add local cache and dedupe.
4. Keep routine status in popup.
5. Show banner only for meaningful risk.
6. Add safety-page routing.
7. Add feedback abuse controls.
8. Add Playwright extension tests.
9. Prepare Chrome and Edge package validation.

## Phase 6 - Public, consumer, and admin completion

1. Complete public lookup.
2. Sign badge payloads.
3. Complete safety page.
4. Complete consumer scan, report, appeal, device, and license pages.
5. Complete review, appeal, provider, identity, and audit admin pages.
6. Add accessible loading, empty, error, and disconnected states.
7. Complete role-based navigation.

## Phase 7 - Website registration and DNS

1. Site-owner onboarding.
2. DNS TXT challenge issuance and scheduled recheck.
3. `.well-known/hip.json` verification.
4. Domain ownership history.
5. Revocation and transfer flow.
6. Public verification display.
7. CoreDNS automated integration tests.

## Phase 8 - Second Life HUD MVP

1. License activation.
2. HIP URL lookup API optimized for HUD use.
3. Private warning levels.
4. Demo mode.
5. Privacy-safe reporting.
6. Marketplace setup documentation.

## Phase 9 - Hardened providers, AI, and sandbox

1. External provider worker queues.
2. Circuit breakers and cache policy.
3. Browser sandbox container isolation.
4. Strict SSRF controls.
5. Optional AI explanation and rule-suggestion provider.
6. Reviewer feedback loop.

## Phase 10 - Production readiness

1. Threat model review.
2. Security test and external review.
3. Load test.
4. Backup and restore drill.
5. Deployment runbook.
6. Incident response runbook.
7. Privacy and retention review.
8. Version 1.0 release checklist.

# 28. Priority Backlog

## P0 - Must happen before public production

- Remove source-controlled local keys.
- Production authentication and MFA.
- Development auth isolation.
- Database migrations.
- Distributed replay and dedupe.
- Signed protocol envelopes and receipts.
- Production key management and revocation.
- SSRF-safe scanning.
- Durable outbox and worker queue.
- Critical rule approval and rollback.
- Real data only in admin UI.
- Secret and dependency scanning.
- Backup and restore test.

## P1 - Required for strong MVP value

- Browser extension hardening.
- Domain ownership onboarding.
- Full scoring caps and confidence.
- Provider normalization and slow path.
- Consumer portal completion.
- Appeals and reputation review.
- Signed live badge.
- Full audit views.
- Playwright end-to-end tests.

## P2 - Expansion

- Second Life HUD release.
- AI-assisted explanations and rule drafts.
- File and image clients.
- Email and chat adapters.
- Enterprise DNS resolver.
- Federation.

# 29. Acceptance Criteria for HIP MVP

HIP MVP is ready for a controlled public beta only when all statements below are true:

- A browser extension can score a public site without collecting private field values or full page text.
- Domain, page, content risk, final score, confidence, reasons, and warnings are shown separately.
- Unknown clean sites do not become Trusted.
- Verified origin does not hide risky content.
- Known phishing or malware evidence produces a clear dangerous result.
- Public scans and feedback have rate limits, dedupe, and poisoning controls.
- Privileged admin actions require real authentication and policy authorization.
- Critical rule actions require two-person approval and can be rolled back.
- HIP envelopes and trust receipts can be signed and verified.
- Replays, expired messages, tampering, and revoked keys are rejected.
- Domain ownership can be verified through DNS TXT and `.well-known`.
- Public badges are live and verifiable.
- All dashboard data is real or clearly empty.
- PostgreSQL backups can be restored.
- No production secret is stored in source control.
- Full build, tests, security checks, and core end-to-end tests pass.

# 30. First Codex Assignment

Codex should not attempt the entire roadmap in one session.

The first assignment is Phase 0, Work Package 1: Repository Truth and Gap Map.

Required output:

1. Inspect the entire current solution and clients.
2. Create `docs/current-state-gap-map.md`.
3. List every existing feature, route, UI page, domain model, application service, infrastructure adapter, database entity, test group, and known placeholder.
4. Map each item in this specification to:
   - Complete.
   - Partial.
   - Missing.
   - Needs security review.
   - Needs tests.
5. Identify duplicate API implementations between HIP.ApiService and HIP.Web.
6. Identify hard-coded secrets or unsafe defaults.
7. Identify development-only authentication paths.
8. Identify uses of in-memory state that must become distributed before production.
9. Identify database startup behavior and migration gaps.
10. Do not implement feature changes during this assignment unless needed to make the inventory tooling work.

Definition of done:

- Only the gap-map document and any necessary non-destructive documentation links are changed.
- No existing feature is removed.
- Full repository status is reported.
- The next smallest safe implementation work package is recommended.

# Appendix A - Recommended Repository Documentation Set

Codex should maintain these documents:

```text
docs/
  architecture.md
  protocol.md
  scoring.md
  rules-engine.md
  privacy.md
  threat-model.md
  current-state-gap-map.md
  api-contracts.md
  data-model.md
  deployment.md
  incident-response.md
  local-testing.md
  ui-test-checklist.md
  second-life-hud.md
```

# Appendix B - Source Notes

Technical baseline sources checked while preparing this specification:

- Microsoft .NET support policy, updated June 9, 2026.
- Microsoft Learn, What's new in C# 14.
- Microsoft Aspire release notes, Aspire 13.4.6, released June 20, 2026.
- Microsoft Learn `System.Security.Cryptography.MLDsa` API documentation.
- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard.
- Current `daCodez/HIP` README, AGENTS.md, solution file, AppHost, API host, Web host, and project files.
