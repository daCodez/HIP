# HIP Implementation Backlog

This backlog is derived from the HIP Master Product Plan and Technical Specification. Codex should complete one work package at a time.

## Work Package Template

Each work package must include:

- Goal
- Existing code inspected
- Files expected to change
- Security and privacy risks
- Acceptance criteria
- Tests
- Rollback plan
- Final change report

## Phase 0 - Current Foundation Hardening

### HIP-0001 Repository truth and gap map
Create `docs/current-state-gap-map.md`. No feature implementation.

### HIP-0002 Remove source-controlled local keys
Move local encryption and hashing keys out of AppHost constants and into user secrets/environment configuration. Reject unsafe defaults outside Development.

### HIP-0003 Lock down development authentication
Prove development auth cannot activate outside Development or from non-loopback traffic. Add authorization regression tests.

### HIP-0004 Database migration safety
Replace production schema creation with migrations and controlled startup validation. Keep explicit test database initialization.

### HIP-0005 Distributed duplicate and replay foundation
Add Redis-backed adapters for duplicate submission and nonce storage. Keep in-memory adapters for explicit tests.

### HIP-0006 Aspire patch upgrade
Update Aspire packages to the latest approved 13.4 patch in a dedicated change. Run full local orchestration tests.

### HIP-0007 CI security baseline
Add secret scanning, dependency vulnerability checks, build, tests, and architecture checks.

## Phase 1 - Protocol

### HIP-0101 Protocol envelope models
Add versioned envelope, issuer, subject, content digest, claims, and signature models.

### HIP-0102 Canonical JSON service
Implement RFC 8785 canonicalization behind an interface with deterministic fixtures.

### HIP-0103 Signature provider factory
Add provider strategy, factory, capability checks, and safe development provider separation.

### HIP-0104 ML-DSA-65 provider
Implement ML-DSA-65 using supported .NET cryptography APIs. Fail closed in production when unsupported.

### HIP-0105 Key lifecycle
Add key states, rotation, retirement, revocation, and audit behavior.

### HIP-0106 Replay protection
Add timestamp tolerance, nonce storage, message ID dedupe, and failure policies.

### HIP-0107 Envelope verification
Validate schema, version, expiry, issuer, key state, signature, and replay state.

### HIP-0108 Signed trust receipts
Issue and verify signed receipts containing score layers, confidence, reasons, policy version, and evidence digest.

## Phase 2 - Identity and Authorization

### HIP-0201 Production authentication
Add real user authentication and secure session behavior.

### HIP-0202 Privileged MFA
Require MFA for Owner and Administrator.

### HIP-0203 Route authorization matrix
Test every admin, consumer, and privileged API route against all roles.

### HIP-0204 Device registration
Add generated device identity, public key, signed challenge, trust state, and revocation.

### HIP-0205 API client credentials
Add scoped service client registration and authentication.

## Phase 3 - Scoring and Providers

### HIP-0301 Formal scoring pipeline
Implement distinct domain, page, content risk, final score, and confidence stages.

### HIP-0302 Score caps and overrides
Add confirmed-threat, executable-download, unknown-evidence, and user-generated-content rules.

### HIP-0303 Reason catalog
Create stable reason codes, warnings, impacts, and plain-language explanations.

### HIP-0304 Provider result contract
Normalize provider status, signals, confidence, latency, freshness, and privacy classification.

### HIP-0305 Slow-path provider jobs
Move external provider work to durable background jobs.

### HIP-0306 Scoring regression suite
Implement all mandatory score scenarios from the master spec.

## Phase 4 - Rules and Review

### HIP-0401 Versioned rule schema
Add schema version, impact, creator, approval, effective time, and rollback fields.

### HIP-0402 Typed field and operator catalog
Reject unsupported fields, operators, and invalid type comparisons.

### HIP-0403 Simulation persistence
Store simulation inputs, results, failed cases, confidence, and recommended mode.

### HIP-0404 Approval workflow
Add one-person and two-person approval policies based on impact.

### HIP-0405 Rollback
Add controlled rollback to a prior rule version or disabled state.

### HIP-0406 AI draft-only rule suggestions
Allow AI to create draft suggestions only. Require simulation and human approval.

## Phase 5 - Browser Extension

### HIP-0501 Permission and CSP audit
Minimize Manifest V3 permissions and validate extension CSP.

### HIP-0502 Extension message validation
Validate all content-script, service-worker, popup, and API messages.

### HIP-0503 Fast scan cache and dedupe
Add local result cache, scan coalescing, and freshness behavior.

### HIP-0504 Popup and banner policy
Keep routine results in popup. Show banners only for meaningful risk.

### HIP-0505 Signed browser client
Add installation registration and optional signed high-trust submissions.

### HIP-0506 Extension end-to-end tests
Add Playwright coverage for popup, banner, feedback, safety routing, and API failure.

## Phase 6 - Portals and Public Surfaces

### HIP-0601 Signed live badge
Use live data and a signed badge payload or receipt.

### HIP-0602 Safety page
Add clear warning flow, safe target display, Go Back, and controlled Continue.

### HIP-0603 Consumer portal completion
Complete protection, scans, reports, appeals, alerts, devices, licenses, and account security.

### HIP-0604 Admin data truth
Ensure every admin card and list uses live stored data or a clear empty/disconnected state.

### HIP-0605 Admin rule builder
Provide simple controls, visible JSON, advanced JSON editing, validation, simulation, approval, and rollback.

## Phase 7 - Domain Verification

### HIP-0701 Site-owner onboarding
Add domain claim and verification challenge flow.

### HIP-0702 DNS TXT verification lifecycle
Add issuance, check, expiry, scheduled recheck, and revocation.

### HIP-0703 Well-known verification
Add signed `.well-known/hip.json` verification.

### HIP-0704 CoreDNS test automation
Automate valid, invalid, timeout, multiple-record, and punycode scenarios.

## Phase 8 - Second Life

### HIP-0801 HUD license activation
Add safe license and setup-code flow.

### HIP-0802 HUD lookup contract
Create a compact privacy-safe URL lookup response.

### HIP-0803 HUD warning levels
Implement low HUD-only, medium private warning, and high private plus optional popup.

### HIP-0804 HUD demo and documentation
Add marketplace demo mode and setup guide.

## Phase 9 - Sandbox and AI

### HIP-0901 Durable sandbox jobs
Add queue, lease, timeout, cancellation, retries, and dead-letter behavior.

### HIP-0902 Sandbox isolation
Add container, network, CPU, memory, file, and output restrictions.

### HIP-0903 SSRF-safe browser execution
Block private and reserved targets and verify resolved/connected IPs.

### HIP-0904 AI explanation provider
Add optional redacted explanation assistance behind an interface.

## Phase 10 - Production Readiness

### HIP-1001 Threat model
Document assets, actors, trust boundaries, threats, and controls.

### HIP-1002 Load testing
Test public lookup, browser fast scans, feedback, and admin lists.

### HIP-1003 Backup and restore drill
Prove PostgreSQL and key metadata recovery.

### HIP-1004 Deployment runbook
Document staging and production deployment, migration, rollback, and secret setup.

### HIP-1005 Incident response
Document detection, containment, key compromise, malicious rule, data leak, and provider compromise procedures.
