# HIP Current-State Gap Map

Last verified: 2026-07-16
Backlog package: HIP-0001
Repository branch at creation: `codex/complete-backlog`

## Purpose

This document maps the current HIP repository to the master product plan and
technical specification. It is an implementation inventory, not a claim that
the MVP is production-ready. A foundation can be present while the production
feature remains partial.

## Status Definitions

| Status | Meaning |
|---|---|
| Complete | The currently specified repository-level behavior is implemented and has relevant automated coverage. |
| Partial | A usable MVP path or foundation exists, but one or more acceptance criteria or production requirements remain. |
| Missing | No coherent implementation of the specified capability was found. |
| Needs security review | Security-sensitive behavior exists but has not yet passed the production controls required by the master specification. |
| Needs tests | Meaningful behavior exists without sufficient automated or runtime coverage to call the package complete. |

Statuses can be combined. For example, `Partial; Needs security review` means
the code is real and reachable but must not be described as production-safe.

## Executive Summary

HIP is a substantial MVP foundation. The repository contains working site
safety scanning, layered scoring, public lookup, browser-extension protection,
privacy-safe feedback, rules and simulation, review workflows, identity and
development signing, PostgreSQL persistence, admin and consumer portals, and a
Second Life HUD foundation.

The highest-risk gaps are production authentication, secret and key management,
database migrations, distributed replay and deduplication, signed protocol
envelopes and trust receipts, production cryptographic key lifecycle, durable
worker queues, SSRF-safe sandbox execution, critical rule approval, and
production operations. These gaps prevent a controlled public production
release.

## Repository Projects and Dependencies

| Area | Status | Current implementation | Remaining gap |
|---|---|---|---|
| `HIP.Domain` | Complete for MVP foundation | Identity, reporting, reputation, review, risk, rules, safety, scoring, and self-healing domain types. | Protocol envelope, trust receipt, nonce, key-lifecycle, and device-registration domain models. |
| `HIP.Application` | Partial | Services and contracts for all current MVP feature areas. Domain rules generally remain independent from hosting and persistence. | Production protocol, auth-client, durable-job, normalized-provider, and complete approval services. |
| `HIP.Infrastructure` | Partial; Needs security review | EF repositories, PostgreSQL/SQLite selection, DNS resolver, generic encrypted record storage, scan aggregates, and runtime stores. | Migrations, production key management, Redis adapters, durable queues/outbox dispatch, normalized hot tables, and recovery procedures. |
| `HIP.ApiService` | Partial | Versioned public, browser, domain-verification, provider-settings, and site-safety APIs. | Consolidate duplicated Web/API routes and add production protocol/client routes. |
| `HIP.Web` | Partial; Needs security review | Blazor portals plus public, consumer, admin, identity, rules, review, reporting, reputation, Second Life, and AI APIs. | Production authentication, account isolation, complete approval UX, and removal of remaining MVP state. |
| `HIP.SandboxWorker` | Partial; Needs security review; Needs tests | Worker project and Aspire registration exist; browser execution is disabled by default. | Durable jobs, leases, retries, dead letters, resource isolation, outbound network policy, and DNS-rebinding-safe SSRF controls. |
| `HIP.AppHost` | Partial; Needs security review | Orchestrates API, Web, PostgreSQL, Redis, CoreDNS, sandbox resources, and secret persistence-protection parameters. | Production secret-store operations and remaining orchestration hardening. |
| `HIP.ServiceDefaults` | Partial | Health, resilience, service discovery, OpenTelemetry, and common hosting defaults. | Domain metrics/spans, production export/retention policy, and alert definitions. |
| `HIP.Tests` | Partial | Broad unit and integration coverage across current feature areas. | Restore full green suite, add complete authorization matrix, migrations, Redis, protocol, sandbox, load, restore, and real-browser coverage. |

The solution is a modular monolith with appropriate extraction seams. Splitting
it into microservices is not required for the MVP.

## Domain and Application Capabilities

| Capability | Status | Evidence in the repository | Remaining gap |
|---|---|---|---|
| Layered HIP scoring | Partial | Domain/page/content/final scores, confidence, status, reasons, warnings, deterministic policies, and accuracy tests. | Complete mandatory caps, stable reason catalog, production calibration, and all master-spec regression scenarios. |
| Site-safety scanning | Partial | Privacy-safe observations, link/download/login risk, rules, feedback evidence, admin-review evidence, and stored results. | Live threat providers, server-side redirect resolution, durable cache, and real sandbox evidence. |
| External evidence providers | Partial; Needs security review | Provider contracts, resilience, freshness/cache foundation, SSL Labs, and disabled Google Web Risk/VirusTotal foundations. | Normalized result contract, durable slow path, credential handling, operational limits, and production integrations. |
| Reputation and feedback | Partial; Needs security review | Reputation profiles/events, weighted feedback, decay, public feedback, duplicate guards, and scan evidence integration. | Abuse-resistant reporter identity, distributed dedupe, production tuning, and approved-override mutation. |
| Privacy-safe reporting | Partial | Validators, hashing, retention model, risk-finding/report ingestion, review/self-healing connections, and EF repository options. | Automated retention cleanup, production trust enforcement, and durable asynchronous ingestion. |
| Review queue and appeals | Partial | Review items, assignment and decisions, appeals, reputation override requests, generated scan signals, audit entries, APIs, and admin pages. | Notifications, complete durable audit policy, two-person critical approvals, and production identity binding. |
| Rules and simulation | Partial | JSON rules, typed fields/operators/actions, validation, matching, evaluation, simulation, persistence, admin builder, activation, disable, and latest-version rollback. | Complete version metadata, impact policy, version browser, explicit rollback target, two-person approval, and full audit history. |
| Self-healing | Partial | Deterministic pattern detection, candidate generation, suggestions, review decisions, simulation, and rollback-plan foundation. | Production clustering, durable metrics, automated rollback execution, signed provenance, and optional AI assistance. |
| AI risk assistance | Partial; Needs security review | Provider interface, redacted deterministic development analyzer, analysis endpoints, and draft-only suggestions. | Production provider, bounded consumption, operational review, and evidence that model output remains non-authoritative. |

## Persistence, PostgreSQL, Redis, and Runtime State

### Implemented

- PostgreSQL is the normal Aspire/runtime database.
- SQLite is available for explicit isolated tests.
- EF repositories cover identities, website identities, domain-verification
  requests, scans, rules, simulations, reports, reputation, review, appeals,
  audit, generated candidates, platform connections, feedback, inbox, and
  outbox records.
- Generic records are serialized and encrypted before persistence.
- Dedicated browser-scan and dashboard aggregate entities support current hot
  paths.

### Partial or missing

| Requirement | Status | Gap |
|---|---|---|
| Production schema lifecycle | Missing; Needs security review | Startup schema creation must be replaced by migrations and controlled validation. |
| PostgreSQL indexes and normalized hot tables | Partial | Generic JSON records remain common; production query/index requirements are incomplete. |
| Redis cache | Missing | Redis is orchestrated but application caching remains in-process. |
| Distributed duplicate/replay storage | Missing | Duplicate guards and relevant caches are process-local. |
| Distributed rate limiting | Missing | Framework policies exist, but no shared Redis-backed state is wired. |
| Durable outbox delivery | Partial | Inbox/outbox persistence types exist; durable dispatch and operational recovery are incomplete. |
| Durable worker queue | Missing | No production queue consumer with leases, retries, cancellation, or dead-letter handling. |
| Backup and restore | Missing | No verified PostgreSQL/key-metadata restore drill or runbook. |

Known or documented MVP state that may still be scoped/in-memory includes
consumer settings and portions of review, appeal, override, reputation,
licensing, provider cache, duplicate protection, and safety-report workflows.
Each must be verified during its owning work package rather than assumed durable
because an EF repository exists elsewhere in the solution.

## API Route Inventory and Duplication

### HIP.ApiService route groups

- Domain verification check.
- Public domain lookup, badges, and feedback.
- Browser score-site, scan-links, scan-result submit, and scan-result lookup.
- Site-safety scan, external evidence check, and extension-scoped provider
  settings.

### HIP.Web route groups

- Public lookup, badges, appeals, feedback, and risk findings.
- Reports, dashboard summaries, scan details, and platform connections.
- Browser and site-safety routes.
- Safety evaluation and reporting.
- Admin site-safety rules and simulations.
- AI analysis and rule suggestions.
- Consumer status, scans, reports, appeals, and settings.
- Second Life HUD, licenses, and simulation.
- Self-healing, review, appeals, overrides, reputation, identity, signing,
  domain verification, rules, simulations, audit, and admin-provider routes.

### Duplicate route surfaces

The following behavior exists in both `HIP.ApiService` and `HIP.Web` and needs
an explicit ownership/consolidation decision before production:

- Public domain lookup and badge responses.
- Public feedback.
- Browser score-site and scan-links.
- Browser scan-result submission and lookup.
- Site-safety scan and external-evidence check.
- Extension-scoped external-provider settings.

Compatibility routes should not be removed without a versioned migration. The
target architecture should select one canonical service implementation and
make any retained Web routes thin forwards or documented compatibility paths.

## Browser Extension

| Capability | Status | Notes |
|---|---|---|
| Manifest V3 automatic scanning | Complete for MVP | Eligible public pages are scanned automatically. |
| Privacy-safe collection | Complete for MVP | Tests prohibit page text/form values and strip private URL components. |
| Popup score experience | Complete for MVP | Shows progress, layered scores, confidence, reasons, warnings, and provider evidence. |
| Warning banner policy | Complete for MVP | Routine results remain in the popup; meaningful risk can show banners. |
| Feedback and safety routing | Complete for MVP | Privacy-safe feedback and controlled safety-page routing exist. |
| Cache, coalescing, and dedupe | Partial | Local/process behavior exists; freshness and distributed coordination remain incomplete. |
| Message-boundary validation | Partial; Needs security review | Guards exist, but every content/background/popup/API message shape needs a formal audit. |
| Permissions and CSP | Partial; Needs security review | Manifest is constrained, but HIP-0501 audit is not complete. |
| Signed installation/client | Missing | No device registration or signed high-trust submission path. |
| Real-browser end-to-end tests | Missing; Needs tests | Node tests cover 105 cases; Playwright/Chromium flows are not implemented. |

## Public, Consumer, and Admin UI

| Surface | Status | Current implementation | Remaining gap |
|---|---|---|---|
| Public lookup | Complete for MVP | Lookup routes/pages show stored score, verification, reasons, and warnings. | Signed receipts and broader matching policy. |
| Live badge | Partial; Needs security review | Live response, script, and embed UI exist. | Cryptographic signature and client verification. |
| Safety page | Partial | Safe target display, risk behavior, Go Back, and controlled Continue exist. | Final-destination resolution and fully persisted reporting workflow. |
| Consumer portal | Partial; Needs security review | Overview, scans, reports, appeals, devices, and settings routes exist. | Real account/license isolation, persistent settings, trusted identities, alerts, and account security. |
| Admin portal | Partial; Needs tests | Broad pages exist for operational features and use live/no-data states in core dashboard paths. | Verify every page against real storage, complete metrics, reconcile dashboard contract tests, and finish approval UX. |
| Admin authentication | Partial; Needs security review | Development headers/local-password provider, roles, policies, and audit foundations exist. | Production identity provider, secure sessions, MFA, and exhaustive route authorization matrix. |

## Identity, Signing, Keys, and Replay

| Requirement | Status | Gap |
|---|---|---|
| Identity and website registration | Partial | Registration, lookup, verification, retry, and revocation foundations exist. Production account ownership remains incomplete. |
| Development signing and verification | Complete only as a development foundation | The provider demonstrates origin/integrity behavior and must not be described as production-safe or post-quantum. |
| Signature provider strategy/factory | Missing | Development and future production providers are not selected through a capability-aware factory. |
| ML-DSA-65 | Missing | No supported production provider is implemented. |
| Key lifecycle | Missing; Needs security review | Rotation, retirement, expiry, compromise, revocation enforcement, and protected storage are incomplete. |
| Canonical JSON | Missing | RFC 8785 canonicalization and fixtures are absent. |
| HIP envelope | Missing | Versioned issuer, subject, claims, digest, signature, and expiry envelope is absent. |
| Replay defense | Missing; Needs security review | No complete timestamp/nonce/message-ID/replay policy backed by distributed storage. |
| Trust receipts | Missing | No signed score/evidence/policy receipt or verification API. |
| Device registration | Missing | No generated device identity, signed challenge, trust state, or revocation. |
| API client credentials | Missing | No scoped service-client registration/authentication. |

## Domain Verification and CoreDNS

| Capability | Status | Notes |
|---|---|---|
| DNS TXT challenge/check | Partial | Request models, repositories, DNS resolver, and verification endpoints exist. |
| Website onboarding | Partial | Admin website registration and retry/revoke flows exist. Production account ownership is incomplete. |
| Verification lifecycle | Partial; Needs security review | Issuance/check exists; scheduled recheck, expiry policy, and complete revocation lifecycle remain. |
| `.well-known/hip.json` | Partial | Document and signed-identity foundations exist; complete production verification lifecycle is missing. |
| CoreDNS local lab | Partial; Needs tests | Aspire/local verification foundation exists. Invalid, timeout, multi-record, and punycode automation is incomplete. |

Domain control must remain separate from safety and reputation. A valid DNS or
well-known proof must never automatically produce a Trusted safety result.

## Reputation, Reports, Reviews, and Appeals

| Capability | Status | Remaining gap |
|---|---|---|
| Weighted feedback | Partial; Needs security review | Production reporter identity, poisoning resistance, distributed dedupe, and calibration. |
| Reputation events/profiles | Partial | Durable behavior must be verified end-to-end; override approvals are not fully merged into scoring. |
| Privacy-safe reports | Partial | Automated retention, queueing, and production reporter trust. |
| Review queue | Partial | Production identity binding, notifications, approval policy, and durable operations review. |
| Appeals | Partial | Notification/status lifecycle and account isolation. |
| Reputation overrides | Partial; Needs security review | Two-person critical approval, durable mutation, expiry, rollback, and audit completeness. |
| Audit | Partial | Production retention, tamper evidence, export, and complete privileged-action coverage. |

## Second Life and Licensing

| Capability | Status | Notes |
|---|---|---|
| HUD scripts and link detection | Partial; Needs tests | LSL scripts, chat shield, link detector, and configuration examples exist. Real Second Life runtime testing remains. |
| Setup-code activation | Partial; Needs security review | Activation and administrative lifecycle APIs exist; production identity, persistence, and abuse controls remain. |
| Privacy-safe scan contract | Complete for MVP | Compact URL-risk requests and responses exist. |
| Warning levels | Complete for MVP logic | HUD-only, private warning, and optional popup behavior are modeled. |
| Marketplace release | Missing | Billing, account login, marketplace demo/setup, and operational support are not implemented. |

## Authentication and Authorization

Current role, permission, policy, development-header, and local-password
foundations are useful for local development only. They do not satisfy
production authentication.

Production blockers:

- A real identity provider and secure server-side session lifecycle.
- MFA for Owner and Administrator.
- Loopback-and-Development-only enforcement for every development bypass.
- Exhaustive positive and negative authorization tests for every admin,
  consumer, resource-bound, and privileged API route.
- Account, tenant, device, and license ownership checks.
- Authentication rate limiting, lockout, recovery, and security-event audit.

## Hard-Coded Keys, Secrets, and Unsafe Defaults

Status: `Complete for HIP-0002; production secret operations still need deployment review`.

AppHost now obtains independent record-encryption and privacy-hashing values
from secret Aspire parameters rather than source-controlled literals.
Infrastructure registration immediately rejects missing, built-in development,
weak, placeholder, reused, or unsafe legacy key material outside Development.
No configured value is logged or returned through an API.

Production environments still need an approved managed secret store, rotation
procedure, access policy, and recovery process as part of deployment and key
lifecycle work.

## Tests and Major Untested Paths

### Current coverage

- Unit and integration tests cover scoring, site safety, reporting, reputation,
  identity, DNS, rules, simulations, review, APIs, persistence, security
  foundations, Aspire, containers, performance foundations, Second Life, and
  admin pages.
- The browser extension has 105 passing Node tests covering privacy, automatic
  scanning, popup/banner policy, payloads, feedback, routing, provider settings,
  failures, and version behavior.

### Known verification gaps

- The full .NET suite is not currently green: dashboard source-contract tests
  still expect earlier dashboard markup/build-marker behavior.
- Production auth and the complete role/route matrix are untested because the
  production auth system does not exist.
- No protocol envelope, canonicalization, replay, revoked-key, or trust-receipt
  suites exist.
- No Redis/distributed coordination tests exist.
- No migration-forward/rollback or production-startup safety suite exists.
- No durable queue retry/dead-letter tests exist.
- No hardened sandbox/network/SSRF integration suite exists.
- No Playwright extension end-to-end suite exists.
- No production load, backup, or restore verification exists.
- Real Second Life behavior remains unverified.

Tests must not be weakened merely to make the suite green. Dashboard tests and
the redesigned dashboard implementation need an explicit contract
reconciliation in the owning work package.

## Production Readiness Map

| Backlog package | Status |
|---|---|
| HIP-0001 Repository truth and gap map | Complete with this document |
| HIP-0002 Source-controlled local keys | Complete |
| HIP-0003 Development authentication isolation | Complete |
| HIP-0004 Database migration safety | Missing |
| HIP-0005 Distributed duplicate and replay foundation | Missing |
| HIP-0006 Aspire patch upgrade | Missing verification |
| HIP-0007 CI security baseline | Missing |
| HIP-0101 through HIP-0108 Protocol | Missing, except development identity/signing foundations |
| HIP-0201 through HIP-0205 Identity and authorization | Missing or partial development foundations |
| HIP-0301 through HIP-0306 Scoring/providers | Partial |
| HIP-0401 through HIP-0406 Rules/review | Partial |
| HIP-0501 through HIP-0506 Browser extension | Partial; strong MVP/Node coverage |
| HIP-0601 through HIP-0605 Portals/public | Partial |
| HIP-0701 through HIP-0704 Domain verification | Partial |
| HIP-0801 through HIP-0804 Second Life | Partial |
| HIP-0901 through HIP-0904 Sandbox/AI | Missing or development-only foundations |
| HIP-1001 Threat model | Missing |
| HIP-1002 Load testing | Missing |
| HIP-1003 Backup and restore drill | Missing |
| HIP-1004 Deployment runbook | Missing |
| HIP-1005 Incident response | Missing |

## Security Risks Requiring Priority Treatment

1. Source-controlled or unsafe-default encryption/hashing keys could make
   encrypted records recoverable by anyone with repository access.
2. Development authentication could become an elevation-of-privilege path if
   environment and loopback restrictions fail open.
3. `EnsureCreated`-style production schema initialization can cause unsafe or
   unreviewed schema behavior.
4. Process-local dedupe, rate limits, cache, and replay state fail under multiple
   instances.
5. Server-side URL/provider/sandbox work is an SSRF and resource-exhaustion
   boundary until resolution, connection, redirects, and egress are constrained.
6. Development signatures prove only the development provider's origin and
   integrity; they are not production-safe or post-quantum evidence.
7. Public feedback and scan ingestion remain poisoning and abuse targets until
   identity, distribution, dedupe, and review controls are productionized.
8. Critical rule and reputation actions need independent approval and rollback
   before they can safely affect users.

## Next Smallest Safe Work Package

HIP-0004: make database startup migration-safe.

Acceptance criteria:

- Production startup never creates or mutates the schema through
  `EnsureCreated`.
- Database migrations are explicit, reviewable, and can be applied through a
  controlled operator action.
- Application startup validates schema compatibility and fails with an
  actionable error when required migrations are missing.
- Test hosts keep an explicit, isolated database-initialization path.
- Focused persistence and startup tests prove production fail-closed behavior
  and test initialization behavior.

Rollback is a normal Git revert of the isolated HIP-0004 commit. Any generated
migration must be reviewed for data-loss operations before it is applied.
