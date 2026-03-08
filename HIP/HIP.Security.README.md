# HIP.Security (Phase 2B Guardrails)

This folder contains the security simulation scaffold with explicit layer boundaries and Phase 2B hardening controls.

## Projects

- `HIP.Security.Domain` — core domain contracts (threats, scenarios, policies, telemetry, coverage, approval/audit models).
- `HIP.Security.Application` — use-case handlers + ports/abstractions (execution, repositories, lifecycle guard, audit hooks, approval guardrails).
- `HIP.Security.Infrastructure` — persistence and adapter composition root (in-memory repositories + immutable-style audit recorder + simulator/policy-engine adapter wiring).
- `HIP.Security.PolicyEngine` — coverage/mutation adapter implementations behind Application ports.
- `HIP.Security.Simulator` — replay/campaign execution adapter implementations behind Application ports.
- `HIP.Security.Api` — API endpoints depending on Application use-cases + API mapping boundary.
- `HIP.Security.Cli` — CLI entry points depending on Application use-cases.
- `HIP.Security.Tests` — compile-safe tests and boundary guardrail tests.

## Dependency direction rules

- **Api/Cli -> Application + Infrastructure only** (no direct Simulator contracts/references).
- **Application -> Domain** and Application-defined abstractions only.
- **Infrastructure/PolicyEngine/Simulator -> Application abstractions** (adapters implement ports).
- **Simulator does not depend directly on PolicyEngine** in this phase.

## Phase 2B controls

### 1) Authz + audit guardrails

- API now includes authentication/authorization scaffolding via a placeholder header auth scheme:
  - `X-HIP-Principal` (required)
  - `X-HIP-Role` (optional, defaults to `SecurityOperator`)
- Policy-based role placeholders:
  - `SecurityPolicyRead` (`SecurityReader|SecurityOperator|SecurityAdmin`)
  - `SecurityPolicyWrite` (`SecurityOperator|SecurityAdmin`)
  - `SecurityPolicyPromote` (`SecurityAdmin`)
  - `SecurityCampaignExecute` (`SecurityOperator|SecurityAdmin`)
- Write/promote endpoints are protected with policy authorization.
- Immutable-style audit hook abstraction (`IPolicyAuditRecorder`) records:
  - `policy.create`
  - `policy.simulate`
  - `policy.activate`
  - `policy.rollback` (rejected scaffold events)

### 2) No-auto-activation enforcement

- Auto-promotion from `Draft` to `Active` in one call is removed.
- Required lifecycle path is explicit and guarded:
  1. `Draft -> Simulate`
  2. `Simulate -> Active`
- Unsafe transitions return explicit rejection reason codes (e.g. `RequiresSimulationStage`, `UnsupportedSourceState`, `RollbackNotSupported`).

### 3) Rate limits + input bounds

- Endpoint-level fixed-window rate limits added for sensitive operations:
  - `policy-write`
  - `policy-promote`
  - `campaign-sensitive`
- Input bounds added with data annotations + model validation:
  - Policy draft name/description/rules limits
  - Policy rule key/operator/value length caps
  - Replay request replay-count range
  - Activation/rollback actor metadata max lengths

### 4) Approval model scaffolding

- Approval metadata contract added (`PolicyApprovalMetadata`) with placeholders:
  - `AuthorId`, `ReviewerId`, `ApproverId`, `ChangeTicket`, `ApprovedAtUtc`
- Activation command now requires approval metadata and rejects incomplete approval payloads.
- In-memory approval repository (`IPolicyApprovalRepository`) stores approval metadata per policy.
- Default behavior remains safe: no auto-active transitions.

## Manual commands

From repository root (`HIP/`):

```bash
# Build security subsystem
 dotnet build HIP.sln

# Run tests for security scaffold
 dotnet test HIP.Security.Tests/HIP.Security.Tests.csproj

# API (placeholder endpoints)
 dotnet run --project HIP.Security.Api/HIP.Security.Api.csproj
```

## Operational notes

- Placeholder auth is scaffolding only; replace with production identity provider integration before release.
- Rollback endpoint is scaffolded intentionally as reject-only in Phase 2B (audited but non-executing).
- No heavy benchmark/suite execution is wired by default.
