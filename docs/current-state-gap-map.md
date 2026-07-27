# HIP Current-State Gap Map

Last verified: 2026-07-27
Backlog package: HIP-1005
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

The tracked HIP-0001 through HIP-1005 work packages now have implemented
repository baselines. This is repository-level V1 feature completeness for
local and controlled evaluation, not a production launch, formal compliance
certification, or claim that every deployment control has been proven.

The repository contains working site safety scanning, layered scoring, public
lookup, browser-extension protection, domain-certificate enrollment,
authenticated issuance, recurring monitoring, privacy-safe feedback, sender
profiles, rules and simulation, review and appeal workflows, identity and
development signing, PostgreSQL persistence, admin and consumer portals, and a
Second Life HUD foundation.

The highest-risk gaps are future tenant/account isolation, managed-key and
secret-store operations, durable worker queues, SSRF-safe sandbox execution,
critical rule approval, scoring/provider productionization, and production
recovery and operations. Identity-provider deployment validation and the replay
risk of static service credentials also require explicit operational controls.
These gaps prevent a controlled public production release.

## Repository Projects and Dependencies

| Area | Status | Current implementation | Remaining gap |
|---|---|---|---|
| `HIP.Domain` | Complete for MVP foundation | Identity, protocol envelope, signed trust receipt, nonce/replay, key-lifecycle, owner-scoped device and service-client registration, reporting, reputation, review, risk, rules, safety, scoring, and self-healing domain types. | Remaining production identity and future tenant/account ownership models. |
| `HIP.Application` | Partial | Services and contracts for current MVP features plus canonical signing, envelope verification, replay protection, trust-receipt issuance/verification, formal scoring, durable provider/sandbox jobs, device proof, service clients, and optional redacted explanations. Domain rules generally remain independent from hosting and persistence. | Complete approval, retention, notification, and production-calibration services. |
| `HIP.Infrastructure` | Partial; Needs security review | EF repositories, PostgreSQL persistence and migrations, validation-only startup, encrypted trust-receipt/device/service-client records, atomic global device/key/client bindings, Redis duplicate/replay adapters, and a distributed pre-PBKDF2 service-client attempt limiter. | Production managed-key integration, durable queues/outbox dispatch, normalized hot tables, live Redis failure testing, and recovery procedures. |
| `HIP.ApiService` | Partial | Versioned public, browser, domain-verification, provider-settings, site-safety, protocol receipt, and exclusive `HIP-Service` authentication foundations. Domain-control and external-evidence checks accept either their existing administrator semantics or the matching exact-scope/domain service client without cookie fallback. | Consolidate duplicated Web/API routes and extend least-privilege client authorization only as future operations require it. |
| `HIP.Web` | Partial; Needs security review | Blazor portals plus public, consumer, admin, identity, rules, review, reporting, reputation, Second Life, and AI APIs. Production Web authentication uses provider-neutral OIDC, hardened protected cookie sessions, explicit endpoint policies, principal-bound privileged mutations, a functional owner-isolated device portal, and owner-bound service-client management at `/admin/api`. | Production identity-provider validation, complete approval UX, and removal of remaining MVP state. |
| `HIP.SandboxWorker` | Complete control-plane foundation; live runner pending | Durable leases/retries/dead letters and fail-closed container/network policies exist with focused tests. Browser execution remains disabled by default. | Pinned runner image, broker wiring, and live container/egress proof. |
| `HIP.AppHost` | Partial; Needs security review | Orchestrates API, Web, PostgreSQL, Redis, CoreDNS, sandbox resources, and secret persistence-protection parameters. | Production secret-store operations and remaining orchestration hardening. |
| `HIP.ServiceDefaults` | Partial | Health, resilience, service discovery, OpenTelemetry, and common hosting defaults. | Domain metrics/spans, production export/retention policy, and alert definitions. |
| `HIP.Tests` | Partial | Broad unit and integration coverage across current feature areas, including exhaustive Web/API authorization manifests and principal matrices. | Restore full green suite and add migrations, Redis, sandbox, load, restore, and real-browser coverage. |

The solution is a modular monolith with appropriate extraction seams. Splitting
it into microservices is not required for the MVP.

## Domain and Application Capabilities

| Capability | Status | Evidence in the repository | Remaining gap |
|---|---|---|---|
| Layered HIP scoring | Partial | Versioned, direction-explicit domain/page/content/final stages, separate confidence and freshness, typed privacy-safe evidence, conservative presentation, immutable projections, deterministic composition, trust-receipt/browser projections, and focused regression coverage. | Complete mandatory caps, stable reason catalog, production calibration, and all master-spec regression scenarios. |
| Site-safety scanning | Partial | Privacy-safe observations, link/download/login risk, rules, feedback evidence, admin-review evidence, and stored results. | Live threat providers, server-side redirect resolution, durable cache, and real sandbox evidence. |
| External evidence providers | Partial; Needs security review | Provider contracts, resilience, freshness/cache foundation, SSL Labs, and disabled Google Web Risk/VirusTotal foundations. | Normalized result contract, durable slow path, credential handling, operational limits, and production integrations. |
| Reputation and feedback | Complete for V1 foundation; Needs production security review | Durable reputation profiles/events, sender-specific report ingestion, weighted feedback, decay, anonymous-trust enforcement, duplicate guards, current-window admin interpretation, review signals, and scan evidence integration. | Abuse-resistant production reporter identity, distributed dedupe validation, calibration, and approved-override mutation. |
| Privacy-safe reporting | Partial | Validators, hashing, bounded automated retention cleanup, risk-finding/report ingestion, review/self-healing connections, and encrypted EF storage exist. | Production trust enforcement and durable asynchronous ingestion for every report path. |
| Review queue and appeals | Complete for V1 foundation | Owner-bound consumer appeal submission and status, review items, assignment and decisions, reputation override requests, generated scan/feedback signals, privacy-safe audit entries, protected APIs, and admin pages are implemented. | Production notifications, complete durable audit policy, two-person critical approvals, and deployed identity-provider validation. |
| Rules and simulation | Complete for repository-level Phase 6 | JSON rules, typed fields/operators/actions, exact-definition-bound persisted simulations, immutable version history, impact policy, encrypted independent approvals, admin approval/deployment UX, authoritative deployments, watch-first promotion, controlled rollback, legacy high-impact bypass prevention, and immutable simulated AI drafts with a hard human-authority boundary. | Production may still consolidate remaining legacy rule paths and expand cross-record audit correlation. |
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
| Production schema lifecycle | Complete foundation; deployment proof pending | Development-only additive creation is isolated; production-like startup validates compiled migrations without mutating schema. Controlled deployment migration evidence remains. |
| PostgreSQL indexes and normalized hot tables | Partial | Generic JSON records remain common; production query/index requirements are incomplete. |
| Redis cache | Missing | Redis is orchestrated but application caching remains in-process. |
| Distributed duplicate/replay storage | Complete foundation | Redis adapters exist for duplicate, nonce, and message replay state; live Redis failure/recovery testing remains. |
| Distributed rate limiting | Partial | Service-client authentication uses shared Redis source and source-plus-client work budgets before PBKDF2. Other framework endpoint limiters remain process-local. |
| Durable outbox delivery | Partial | Inbox/outbox persistence types exist; durable dispatch and operational recovery are incomplete. |
| Durable worker queue | Complete foundation | Provider and sandbox jobs have encrypted persistence, compare-and-swap leases, retries, cancellation/terminal state, and worker consumers. Operational alert/replay tooling remains. |
| Backup and restore | Tooling/runbook complete; drill evidence pending | Safe custom-format dump, checksum, key-metadata, isolated restore, and verification workflow exists; target-platform execution is still required. |

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
| Cache, coalescing, and dedupe | Complete for repository-level Phase 5 | Fresh/stale/expired coordination, identical-request coalescing, failure recovery, hashed result-sensitive keys, bounded LRU state, and bounded successful-write dedupe cover the extension fast path. |
| Message-boundary validation | Complete for repository-level Phase 5 | Closed request inventories, extension-context and sender-tab binding, bounded prototype-free copies, strict privacy-safe API-forward contracts, generic errors, and bounded responses cover service-worker and content-script messages. |
| Permissions and CSP | Complete for repository-level Phase 5 | Permanent host access is loopback-only, configured HTTPS HIP hosts require a user grant, extension code is local-only under a strict CSP, content scripts remain isolated, and focused manifest contracts prevent permission drift. |
| Signed installation/client | Complete for repository-level Phase 5 | Consumer-owned non-exportable P-256 keys, proof-of-possession registration/revocation, scoped request proofs, replay rejection, and registered-device provenance are implemented without elevating device proof into a safety signal. |
| Real-browser end-to-end tests | Complete for repository-level Phase 5 | Five serial Playwright/Chromium scenarios cover unpacked startup, consumer registration, suspicious banner/feedback privacy, trusted/API-failure popup behavior, and dangerous-link safety routing. |

## Public, Consumer, and Admin UI

| Surface | Status | Current implementation | Remaining gap |
|---|---|---|---|
| Public lookup | Complete for MVP | Lookup routes/pages show stored score, verification, reasons, and warnings. | Signed receipts and broader matching policy. |
| Live badge | Complete for repository-level Phase 6 | Live normalized lookup data is bound into a five-minute versioned RFC 8785 signed document using the managed signer boundary, explicit issuer/key policy, lifecycle verification, two-host verification APIs, and fail-closed embed scripts. | Production still requires an audited managed signer, an explicitly authorized issuer/key, and operational key publication/revocation procedures. |
| Safety page | Complete for repository-level Phase 6 | Query/fragment-safe target display, separate domain/page/content/final scores, reliable Go Back, risk-tiered confirmation, critical blocking, working reports, and encrypted create-only privacy-hashed decision persistence are implemented. | Network redirect resolution remains intentionally deferred to HIP-0903 so it cannot bypass SSRF and DNS-rebinding controls. |
| Consumer portal | Complete for repository-level Phase 6 | Live owner-bound protection/device overview, privacy-safe scan/report/appeal histories, encrypted optimistic-concurrency alert settings, proof-of-possession device management, explicit account-license isolation, and reduced-claim account-security status are implemented across protected routes with empty/unavailable states. | A future explicit web-account-to-HUD-license linking workflow may add records; HIP correctly refuses to infer ownership or enumerate global licenses today. |
| Admin portal | Complete for repository-level Phase 6 | Every admin page has a maintained data-truth inventory; operational counts use stored projections, unavailable dependencies are distinct from empty sources, navigation has no fake queue badges, and the rule builder exposes JSON validation/copying, persisted simulation, independent approval, version history, activation, watch promotion, and rollback. | Production deployment still needs environment-specific operator validation and monitoring. |
| Admin authentication | Complete foundation | Development authentication is isolated to Development. Other environments use a provider-neutral OIDC confidential code flow with PKCE, explicit claim/role reduction, certificate-protected shared cookie sessions, privileged MFA/step-up, and exhaustive route/page policy tests. | Provider deployment validation, recovery, and security-event audit. |

## Identity, Signing, Keys, and Replay

| Requirement | Status | Gap |
|---|---|---|
| Identity and website registration | Partial | Registration, lookup, verification, retry, and revocation foundations exist. Production account ownership remains incomplete. |
| Development signing and verification | Complete only as a development foundation | The provider demonstrates origin/integrity behavior and must not be described as production-safe or post-quantum. |
| Signature provider strategy/factory | Complete foundation | Capability-aware exact-algorithm selection and explicit development/production runtime policy are implemented without fallback. |
| ML-DSA-65 | Complete provider foundation | The supported .NET ML-DSA-65 provider is implemented and production fails closed when the platform capability is unavailable. Managed key custody remains production integration work. |
| Key lifecycle | Complete foundation | Algorithm-neutral states, fail-closed transitions, historical signing windows, privacy-safe audit evidence, encrypted persistence, and optimistic concurrency are implemented. Managed-key provider linearization remains production integration work. |
| Canonical JSON | Complete foundation | RFC 8785 canonicalization, dependency injection, adversarial vectors, and stable HIP fixtures are implemented. |
| HIP envelope | Complete verification foundation | Strict version-one parsing, canonical signing scope, authoritative issuer/key validation, expiry, fail-closed provider handling, post-crypto state rechecks, and replay enforcement are implemented. The current wire field naming and strict extension policy still require reconciliation with the master-plan example before protocol stabilization. |
| Replay defense | Complete foundation | Server-owned time policy, typed fail-closed outcomes, issuer-scoped message-ID and nonce dedupe, and Redis-backed cross-instance state are implemented and invoked only after valid envelope cryptography. |
| Trust receipts | Complete foundation | Strict immutable version-one score/evidence/policy receipts, deterministic privacy-safe evidence digests, RFC 8785 signing scope, explicit authorized issuer/key policy, managed signer boundary, create-only EF persistence, and matching issue/lookup/verify routes are implemented. Production still requires an audited managed signer and configured authorized receipt key. |
| Device registration | Complete foundation | Owner-scoped opaque device IDs, WebCrypto P-256 keys, digest-only expiring challenges, atomic proof consumption, encrypted state, immutable global bindings, audit, revocation, APIs, and consumer UI are implemented. Device proof establishes key possession only, not safety or reputation. |
| API client credentials | Complete foundation | Owner-derived registrations, exact scopes/domain grants, one-time secrets, client-bound PBKDF2 verifiers, encrypted concurrency-safe persistence, rotation, terminal revocation, privacy-safe audit, distributed pre-KDF limits, no-fallback standalone API authentication, and admin management UI are implemented. Static bearer credentials remain replayable if exposed. |

## Domain Verification and CoreDNS

| Capability | Status | Notes |
|---|---|---|
| DNS TXT challenge/check | Complete foundation | Durable owner-bound issuance, live DNS checks, expiry, rotation, scheduled recheck, terminal revocation, and truthful UI states are implemented. |
| Website onboarding | Complete foundation | Normalized domain claims are bound to authenticated owner scope, with an explicit platform-owner override and encrypted create-only persistence. |
| Verification lifecycle | Complete foundation | Bounded challenges, immutable generations, rechecks, renewal, revocation, audit, and concurrency-safe persistence are implemented. |
| `.well-known/hip.json` | Complete foundation | Owner-bound templates, RFC 8785 signing payloads, registered-key signature checks, fixed HTTPS fetching, public-address pinning, redirect refusal, and response limits are implemented. |
| CoreDNS local lab | Complete automation foundation | Aspire wiring, deterministic valid/invalid/absent/multi-record/segmented/punycode fixtures, always-on decision tests, and a one-command live Docker harness are implemented. The live container cases were not run in the latest pass because Docker was unavailable. |

Domain control must remain separate from safety and reputation. A valid DNS or
well-known proof must never automatically produce a Trusted safety result.

## Reputation, Reports, Reviews, and Appeals

| Capability | Status | Remaining gap |
|---|---|---|
| Weighted feedback | Complete for V1 foundation; Needs production security review | Production reporter identity, poisoning resistance validation, distributed dedupe evidence, and calibration. |
| Reputation events/profiles | Complete for V1 foundation | Approved override mutation is not yet fully merged into production scoring. |
| Privacy-safe reports | Partial | Automated retention, queueing, and production reporter trust. |
| Review queue | Complete for V1 foundation | Production identity-provider validation, notifications, critical approval policy, and durable operations review. |
| Appeals | Complete for V1 foundation | External notifications and production operations integration. |
| Reputation overrides | Partial; Needs security review | Two-person critical approval, durable mutation, expiry, rollback, and audit completeness. |
| Audit | Partial | Production retention, tamper evidence, export, and complete privileged-action coverage. |

## Second Life and Licensing

| Capability | Status | Notes |
|---|---|---|
| HUD scripts and link detection | Complete MVP foundation; live validation pending | The release LSL script performs local detection, privacy-safe HIP lookup, settings, reporting, and owner-only warnings. Real Second Life runtime testing remains. |
| Setup-code activation | Complete foundation | Encrypted durable licenses, bounded-lifetime one-time codes, device-bound credentials, reset/revocation, concurrency controls, and redacted administrative responses exist. Marketplace entitlement integration remains. |
| Privacy-safe scan contract | Complete for MVP | Compact bounded URL-risk requests and responses avoid echoing snippets, URL paths, sender hashes, and device identifiers. |
| Warning levels | Complete for MVP logic | HUD-only, private warning, optional popup, scan mode, and safety-routing preferences are enforced by the service and client. |
| Marketplace demo and setup | Complete MVP foundation | A local-only no-network demo mode and buyer/merchant setup guides exist. Billing, entitlement validation, and live marketplace operational support remain. |

## Authentication and Authorization

HIP-0201 supplies the production Web authentication foundation. Development
headers, local passwords, and development cookies are registered only in the
Development environment. Other environments use a provider-neutral OIDC
confidential authorization-code flow with PKCE and a hardened encrypted Web
session. Validated issuer and subject claims are reduced to privacy-safe HIP
actor/consumer identifiers, and only explicitly configured external roles are
accepted.

HIP-0202 adds fail-closed MFA for Owner and Administrator policies outside
Development and bounded recent authentication for high-impact mutations. Only
validated identity-token `amr`, `acr`, and `auth_time` evidence is reduced into
HIP-owned claims. The explicit antiforgery-protected and rate-limited step-up
flow is actor-bound, preserves the original hard session expiry, and leaves API
failures as 401/403 responses. Critical rule, reputation override, domain
revocation, and license mutations reauthorize immediately before persistence.

HIP-0203 classifies every discovered HTTP endpoint and Razor page as explicitly
anonymous or policy-protected. The maintained closure manifest covers every
currently protected Web API route and page template, every named
admin/consumer/HUD policy, and positive and negative principal combinations.
Mutation audit actors are resolved from the authenticated HIP principal rather
than legacy request fields. Current consumer and HUD caller-owned surfaces apply
consumer or exact license/device resource checks with non-disclosing failures.
A coverage guard fails when a newly mapped endpoint lacks explicit metadata.

HIP-0204 adds an exact consumer-owned device-registration boundary. The server
derives owner scope only from the unique authenticated consumer claim, validates
canonical P-256 SubjectPublicKeyInfo, issues a five-minute RFC 8785 signing input,
and retains only its SHA-256 digest. Completion verifies a fixed-width WebCrypto
signature and atomically consumes the challenge, creates immutable global key
and device bindings, and commits privacy-safe audit evidence. The Web private key
is non-exportable and remains in browser IndexedDB. Revocation is terminal, and
proof of key possession is never presented as device safety or reputation.

HIP-0205 adds an independent owner-bound service-client boundary. Owner and
Admin roles can list registrations; create, credential rotation, and terminal
revocation additionally require recent MFA-backed authentication and cookie
antiforgery validation at the management API. The full static credential is
returned only by create or rotate. HIP stores a client-bound
PBKDF2-HMAC-SHA256 verifier inside encrypted, optimistic-concurrency-controlled
persistence and atomically records privacy-safe lifecycle audits.

`HIP.ApiService` accepts only the exact
`Authorization: HIP-Service <clientId>.<secret>` format for service clients and
does not treat Web cookies as client credentials. Each client has exactly one
supported scope and exact domain grants. Redis-backed source and
source-plus-client budgets run before PBKDF2 and fail closed. Authentication
uses stable 401 responses; exact scope or resource denial returns 403. A static
credential remains replayable if stolen, and successful authentication or
domain control is never a safety or trust verdict.

Remaining production blockers:

- Ownership policy for future tenant/account resource types as they are added.
- Identity-provider deployment validation, recovery, and security-event audit.
- Sender-constrained or signed-request credentials for integrations that cannot
  accept the replay risk of a static bearer secret.

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
- The browser extension has more than 100 Node tests covering privacy, automatic
  scanning, popup/banner policy, formal scoring, payloads, feedback, routing,
  provider settings, failures, and version behavior. Five serial Playwright
  scenarios load the real unpacked extension and cover service-worker/popup
  startup, installation keys, warning/feedback privacy, normal and failed API
  states, and safety-page routing.

### Known verification gaps

- The focused dashboard contract is reconciled with the current implementation:
  all 47 `AdminDashboardTests` pass with isolated build artifacts, including
  rendered routes, source contracts, privacy-safe projections, dependency
  availability, and website-verification lifecycle metrics. The full .NET suite
  was intentionally not rerun as part of this focused work package.
- Focused production authentication, MFA, step-up, device proof, tamper,
  actor-binding, and sensitive-action tests exist. Authorization closure tests
  cover every protected Web API route and page template without rendering
  content for disallowed principals.
- Focused service-client suites cover input contracts, credential protection,
  lifecycle transitions, owner isolation, encrypted persistence, concurrent
  rotation, management APIs/UI, scheme routing, exact scope/domain decisions,
  old/expired/revoked credentials, and pre-verification rate-limit behavior.
- Protocol suites now cover canonicalization, envelope verification, replay,
  revoked keys, receipt tampering, issuer authorization, deterministic evidence,
  persistence conflicts, and both HTTP hosts. External interoperability against
  a production managed signer remains unverified.
- No live multi-instance Redis outage/recovery integration suite exists; atomic
  service-client counter and fail-closed adapter behavior has focused coverage.
- No migration-forward/rollback or production-startup safety suite exists.
- No durable queue retry/dead-letter tests exist.
- No hardened sandbox/network/SSRF integration suite exists.
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
| HIP-0004 Database migration safety | Complete |
| HIP-0005 Distributed duplicate and replay foundation | Complete |
| HIP-0006 Aspire patch upgrade | Complete |
| HIP-0007 CI security baseline | Complete |
| HIP-0101 Protocol envelope models | Complete |
| HIP-0102 RFC 8785 canonical JSON | Complete |
| HIP-0103 Signature provider factory | Complete |
| HIP-0104 ML-DSA-65 provider | Complete |
| HIP-0105 Key lifecycle | Complete |
| HIP-0106 Replay protection | Complete |
| HIP-0107 Envelope verification | Complete |
| HIP-0108 Signed trust receipts | Complete |
| HIP-0201 Production authentication | Complete |
| HIP-0202 Privileged MFA | Complete |
| HIP-0203 Route authorization matrix | Complete |
| HIP-0204 Device registration | Complete |
| HIP-0205 API client credentials | Complete |
| HIP-0301 Formal scoring pipeline | Complete |
| HIP-0302 Score caps and overrides | Complete |
| HIP-0303 Reason catalog | Complete |
| HIP-0304 Provider result contract | Complete |
| HIP-0305 Slow-path provider jobs | Complete |
| HIP-0306 Scoring regression suite | Complete |
| HIP-0401 Versioned rule schema | Complete |
| HIP-0402 Typed field and operator catalog | Complete |
| HIP-0403 Simulation persistence | Complete |
| HIP-0404 Approval workflow | Complete |
| HIP-0405 Controlled rollback | Complete |
| HIP-0406 AI draft-only rule suggestions | Complete |
| HIP-0501 Permission and CSP audit | Complete |
| HIP-0502 Extension message validation | Complete |
| HIP-0503 Fast scan cache and dedupe | Complete |
| HIP-0504 Popup and banner policy | Complete |
| HIP-0505 Signed browser client | Complete |
| HIP-0506 Extension end-to-end tests | Complete |
| HIP-0601 Signed live badge | Complete |
| HIP-0602 Safety page | Complete |
| HIP-0603 Consumer portal completion | Complete |
| HIP-0604 through HIP-0605 Admin portal | Complete |
| HIP-0701 through HIP-0703 Domain verification | Complete foundation |
| HIP-0704 CoreDNS test automation | Complete foundation; live Docker rerun pending |
| HIP-0801 through HIP-0804 Second Life | Complete MVP foundation; live Second Life validation pending |
| HIP-0901 Durable sandbox jobs | Complete foundation |
| HIP-0902 Sandbox isolation | Complete enforceable launch-policy foundation; pinned runner image and live Docker proof pending |
| HIP-0903 SSRF-safe browser execution | Complete network-gate foundation; runner/broker wiring pending |
| HIP-0904 AI explanation provider | Complete optional provider boundary with deterministic fallback |
| HIP-1001 Threat model | Complete baseline; release-by-release review required |
| HIP-1002 Load testing | Harness complete; target-environment evidence pending |
| HIP-1003 Backup and restore drill | Safe tooling/runbook complete; dated target-platform drill pending |
| HIP-1004 Deployment runbook | Complete baseline; target-platform commands/evidence pending |
| HIP-1005 Incident response | Complete baseline; tabletop exercise evidence pending |

## Security Risks Requiring Priority Treatment

1. Source-controlled or unsafe-default encryption/hashing keys could make
   encrypted records recoverable by anyone with repository access.
2. Development authentication could become an elevation-of-privilege path if
   environment and loopback restrictions fail open.
3. `EnsureCreated`-style production schema initialization can cause unsafe or
   unreviewed schema behavior.
4. Process-local rate limits and remaining cache state fail under multiple
   instances; duplicate and replay state now uses Redis.
5. Server-side URL/provider/sandbox work is an SSRF and resource-exhaustion
   boundary until resolution, connection, redirects, and egress are constrained.
6. Development signatures prove only the development provider's origin and
   integrity; they are not production-safe or post-quantum evidence.
7. Public feedback and scan ingestion remain poisoning and abuse targets until
   identity, distribution, dedupe, and review controls are productionized.
8. Critical rule and reputation actions need independent approval and rollback
   before they can safely affect users.
9. Service clients are least-privilege and revocable, but their static bearer
   credentials remain replayable if exposed. Registered-device proof and API
   authentication must not be interpreted as safety or reputation. Registered
   browser submissions remain non-authoritative evidence by design.

## Next Smallest Safe Work Package

Complete the live environment evidence that cannot be truthfully produced from
the current unhealthy local Docker stack.

Acceptance criteria:

- Wire a pinned browser-runner image through the sandbox network gate and prove
  connected-IP/egress/container isolation with live Docker tests.
- Run the load harness in staging and retain p95/error/saturation evidence.
- Execute and audit the PostgreSQL plus secret-metadata restore drill.
- Rehearse deployment rollback and incident-response tabletop procedures.

HIP-0604 adds explicit dashboard dependency availability, removes invented
navigation/client/message counts, and inventories all admin surfaces. HIP-0605
adds immutable rule versions, exact-definition simulation binding, and the full
approval/deployment/rollback UI over the existing durable workflow. HIP-0503 is
complete at the repository level with bounded fresh/stale/expired
coordination, identical-request and stale-refresh coalescing, failure recovery,
canonical privacy-safe hashed keys, deterministic LRU eviction, bounded per-tab
summaries, and bounded successful-write deduplication. The decision is recorded
in ADR-012. HIP-0504 popup/banner policy, HIP-0505 installation-bound request
proof, and HIP-0506 real Chromium coverage are complete. HIP-0601 adds a signed
live-badge document and verification flow; the secure default remains unavailable
until a managed signer and authorized issuer/key are configured. HIP-0602 adds
risk-tiered safety confirmation plus encrypted privacy-hashed decision records;
network redirect resolution stays deferred to HIP-0903. HIP-0603 replaces static
consumer settings and overview placeholders with encrypted owner-scoped state and
complete protected portal navigation. Rollback remains a normal Git revert of the
affected extension, server, and Playwright slices.
