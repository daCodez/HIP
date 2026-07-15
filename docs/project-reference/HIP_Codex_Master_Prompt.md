# Codex Master Prompt - Continue HIP Safely

You are continuing the existing HIP project in the `daCodez/HIP` repository.

HIP means Human Identity Protocol. HIP is the main product. It is a trust and origin verification layer above TCP and TLS. Browser extensions, the Second Life HUD, web portals, and future integrations are clients of HIP.

Read these files before making any change:

1. `AGENTS.md`
2. `docs/HIP_Master_Plan_and_Spec.md` or the supplied master specification
3. `README.md`
4. The existing source and tests related to the assigned work package

# AGENT SAFETY PROTOCOL - REQUIRED

Before editing:

1. Run `rtk git status --short`.
2. Run `rtk git log -5 --oneline`.
3. Do not delete, reset, clean, regenerate, or replace existing work.
4. If the tree is clean, create a checkpoint before a major implementation package.
5. If the tree is dirty, preserve it. Create a timestamped patch backup and untracked-file list. Do not reset it.
6. Make small, testable changes.
7. Never add secrets to source code.
8. Preserve the approved HIP logo, icon set, brand system, and brand integrity tests.
9. Use live data or clear no-data states. Never add fake dashboard activity.

# ENGINEERING REQUIREMENTS

- Target .NET 10 LTS and C# 14.
- Use .NET Aspire.
- Keep Clean Architecture boundaries.
- Keep HIP as a modular monolith for the MVP. Use internal events and extraction seams instead of premature microservices.
- Use PostgreSQL for normal runtime persistence and Redis for distributed cache, dedupe, nonce, and rate-limit needs.
- Use design patterns when they reduce coupling or clarify security boundaries.
- Validate all inputs.
- Add safe structured logging.
- Do not log secrets or private raw content.
- Consider security, performance, privacy, and failure behavior in every method.
- Add XML documentation to every new method and public type.
- Add detailed comments for non-obvious and security-sensitive logic.
- Every new method must be covered by tests. Prefer testing private behavior through public behavior.
- Use cancellation tokens for I/O.
- Use `TimeProvider` in testable time logic.
- Do not invent custom cryptography.

# CURRENT ASSIGNMENT

Complete Phase 0, Work Package 1: Repository Truth and Gap Map.

Create or update:

`docs/current-state-gap-map.md`

The document must inventory the current repository and map the master specification to:

- Complete
- Partial
- Missing
- Needs security review
- Needs tests

Inspect and document:

- Projects and dependencies
- Domain models
- Application services and handlers
- Infrastructure adapters and persistence
- PostgreSQL entities and migrations
- Redis usage and remaining in-memory state
- API routes in HIP.ApiService and HIP.Web
- Duplicate route implementations
- Browser extension features
- Consumer and admin UI pages
- Rules, simulations, approvals, and self-healing
- Identity, signing, keys, and replay protection
- Domain verification and CoreDNS
- Reputation, feedback, reports, reviews, and appeals
- Second Life and licensing
- Sandbox worker status
- Authentication and authorization
- Hard-coded keys, secrets, and unsafe defaults
- Tests and major untested paths
- Production readiness gaps

Do not implement unrelated features during this assignment.

# REQUIRED VERIFICATION

Run the smallest relevant checks needed to confirm the inventory. Do not change behavior only to make tests pass.

At the end, report:

1. Git status before changes.
2. Files changed.
3. Why each file changed.
4. Commands and tests run.
5. Results and failures.
6. Security risks found.
7. The next smallest safe work package.
