# HIP Threat Model

Status: production-readiness baseline. Review this document before each release and whenever a trust boundary, credential, provider, or public contract changes.

## Security objectives

HIP must preserve the origin and integrity of signed evidence, make trust decisions explainable, isolate owners and administrative roles, minimize private data, remain available under abuse, and fail closed when identity, cryptography, persistence, provider, or sandbox controls cannot be established. A valid signature proves origin and integrity only; it does not prove safety or reputation.

## Assets

- signing private keys, verification keysets, device credentials, setup codes, OIDC sessions, service-client secrets, encryption keys, and privacy-hashing keys;
- identity registrations, domain challenges, trust receipts, scan evidence, scores, rules, reputation decisions, reviews, appeals, licenses, audit records, and recovery metadata;
- availability of public lookup, scan ingestion, admin review, provider workers, PostgreSQL, Redis, DNS verification, and sandbox queues;
- user privacy: page contents, URLs and paths, browsing activity, form values, messages, avatar identifiers, reporter identifiers, and account relationships.

## Actors

- anonymous lookup users and unregistered clients;
- registered browser devices, Second Life HUDs, service clients, domain owners, consumers, support staff, reviewers, administrators, and owners;
- external OIDC, DNS, threat-intelligence, reputation, AI-explanation, and future sandbox providers;
- attackers controlling a website, DNS answer, redirect, browser page, extension message, HUD input, public report, service credential, provider response, or compromised operator account;
- infrastructure operators with database, container, secret-store, backup, or deployment access.

## Trust boundaries

1. Untrusted browser/page/HUD input to HIP public APIs.
2. Browser extension page world to content script, service worker, and device credential storage.
3. Anonymous/registered device and service-client authentication to owner-scoped application services.
4. OIDC provider claims to HIP's protected administrative session and role policies.
5. HIP application services to PostgreSQL, Redis, encrypted records, outbox/inbox state, and backups.
6. HIP workers to external DNS, provider, AI, and sandbox execution networks.
7. Control-plane sandbox worker to the disposable untrusted-content container.
8. Development signing provider to any future audited production or post-quantum provider.
9. Operator/admin UI to privileged lifecycle, approval, reset, revocation, export, and recovery actions.

## Threats and controls

| Threat | Implemented controls | Required deployment or remaining control |
|---|---|---|
| Credential theft or replay | Device-bound opaque credentials, keyed verification, revocation/reset checks, service-client scopes, protected OIDC cookies, replay/dedupe stores, no secret listing after handoff | Secret-store rotation, short-lived production credentials where supported, alerting, tested emergency revocation |
| Cross-owner access or IDOR | Owner-derived partitions, resource-bound authorization handlers, explicit admin policies, route-authorization closure tests | Production IdP claim mapping review and periodic access recertification |
| Public ingestion poisoning | Input validation, rate limits, dedupe, reporter trust levels, non-authoritative browser evidence, review queues | Distributed abuse telemetry, tuned production quotas, notification and moderation staffing |
| Signature/key confusion | Versioned envelopes, canonical payloads, registered keysets, runtime policy, expiry, algorithm identifiers | Audited production provider, HSM-backed key lifecycle, post-quantum migration evidence |
| SSRF and DNS rebinding | Scheme/port/credential bounds, public-address classification, pre-resolution, redirect revalidation, connected-IP equality policy | Wire the gate to a pinned live browser runner and prove egress enforcement in deployment |
| Malicious page/container escape | Separate disposable-container launch contract, no ambient network, read-only root, no capabilities, non-root user, no-new-privileges, PID/CPU/memory/tmpfs/time/output limits | Pinned runner image, vulnerability scanning, seccomp/AppArmor or equivalent, live escape and egress tests |
| Provider compromise or malformed evidence | Providers supply bounded normalized evidence and never decide the HIP score; circuit/cache/job boundaries and deterministic fallback | Production provider allowlist, credentials, SLAs, monitoring, and compromise runbook |
| AI prompt injection or data leakage | Optional provider receives only structured score facts and signal codes; output is bounded and URL/control-text rejected; AI cannot change scores | Provider-specific data-processing review, retention controls, and explicit enablement |
| Stored-data disclosure or tampering | Authenticated record encryption, privacy hashes, versioned compare-and-swap state, owner isolation, redacted public DTOs | Managed key storage/rotation, backup encryption, tamper-evident audit export, restore drill |
| Queue loss, duplicate work, or stuck execution | Durable jobs, atomic leases, expiry/reclaim, bounded retries, cancellation, stale-token rejection, dead-letter state | Dead-letter alerting, operational replay procedure, capacity monitoring |
| Privileged abuse | Role policies, principal-bound mutations, critical approval foundations, audit records, redacted admin data | Independent approval completion for every critical path, SIEM export, retention and alert review |
| Availability exhaustion | Request-size limits, bounded collections, timeouts, rate limits, async slow work, caches, batch limits | Load tests, autoscaling, database/Redis capacity thresholds, DDoS controls |
| Client overclaim or privacy leak | Thin clients, local pre-filtering, bounded snippets, no full chat/IM logs, owner-only HUD warnings, honest platform limitations | Store review, real-browser and real-Second-Life validation, privacy-policy review |
| Unsafe deployment or rollback | Environment validation, production rejection of demo keys, explicit maintenance jobs, health telemetry | Migration strategy, immutable artifacts, deployment/rollback runbook, backup checkpoint and recovery exercise |

## Abuse cases that must remain tested

- a device credential is used for another device, owner, or revoked license;
- a domain challenge, signed document, nonce, setup code, or service credential is replayed;
- a public request submits oversized collections, private content, local URLs, credentials-in-URL, redirects to metadata services, or DNS answers that change before connect;
- two workers claim the same job, a worker crashes during a lease, or a stale lease reports completion;
- a provider returns mismatched target identity, excessive output, contradictory evidence, private content, or hostile explanation text;
- an administrator accesses or mutates a resource outside policy or attempts a critical decision without independent approval;
- production starts with development authentication, demo keys, unsafe database initialization, an unpinned sandbox image, or disabled mandatory dependencies.

## Logging and privacy rules

Logs may contain bounded operational identifiers, normalized public domains, stable reason/status codes, durations, and aggregate counts. Logs must not contain credentials, setup codes, cookies, authorization headers, encryption keys, raw URLs or paths, page text, form data, private messages, avatar/account identifiers, provider response bodies, or sandbox output. Exception logging must use safe classifications rather than untrusted bodies.

## Release gates and residual risk

A production release is blocked until production identity configuration, secret/key storage, schema migration, backup/restore, incident response, load evidence, and monitoring are in place. Live browser sandboxing is also blocked until a pinned image is wired through the network gate and its container/egress controls are proven on the target platform. The development signing provider and placeholder signatures must never be represented as production-safe or post-quantum-ready.

The security owner records accepted residual risks with an expiry and reviewer. Critical unresolved risks require explicit owner sign-off; documentation alone is not a compensating control.
