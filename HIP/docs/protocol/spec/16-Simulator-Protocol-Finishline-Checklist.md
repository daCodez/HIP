# HIP Simulator Protocol-First Finish Line Checklist

Status legend: `[ ]` not started, `[~]` in progress, `[x]` done.

## Goal
Make HIP simulator run directly against protocol primitives (not only app behavior), while preserving application-mode regression coverage.

## Phase 0 — Control and safety
- [x] Create strict finish-line checklist and execute in order.
- [x] Keep each phase buildable (`dotnet build HIP.sln`) before moving on.
- [x] Keep docs/tests synced with every behavior/interface change.

## Phase 1 — Execution mode plumbing
- [x] Add `SimulationExecutionMode` model (`application|protocol|hybrid`).
- [x] Add scenario-level `executionMode` support with default `application`.
- [x] Add CLI override `--mode application|protocol|hybrid`.
- [x] Update scenario schema with `executionMode` enum.
- [x] Add explicit runner guard for non-application modes until protocol target is implemented.

## Phase 2 — Protocol execution target
- [x] Add `ISimulationExecutionTarget` abstraction.
- [x] Implement `ApplicationExecutionTarget` (current evaluator path).
- [x] Implement `ProtocolExecutionTarget` using HIP.Protocol + HIP.Protocol.Security services.
- [x] Route scenario execution by effective mode (scenario mode + CLI override).

## Phase 3 — Protocol step model + validation
- [x] Add protocol-step schema/types (`sign`, `verify`, `issue-receipt`, `verify-receipt`, `challenge`, `replay`, `timestamp-skew`, `key-revoked`, `key-replaced`).
- [x] Validate mode-step compatibility (e.g., protocol mode requires protocol step set).
- [x] Add seed protocol scenarios (`HIP.Simulator.Cli/scenarios/protocol/*`).

## Phase 4 — Reporting and UX parity
- [x] Include execution target/mode in JSON/HTML/Markdown reports.
- [x] Split summaries: protocol findings vs application findings.
- [x] Expose mode filter/selector in Web/Admin simulator pages.
- [x] Auto-reattach UI to active run after page reload/navigation.

## Phase 5 — Tests and guardrails
- [x] Add simulator tests for protocol mode routing and core protocol flows.
- [x] Add replay/timestamp/key-lifecycle protocol scenarios and assertions.
- [x] Run and pass:
  - [x] `dotnet test HIP.Simulator.Tests`
  - [x] `dotnet test HIP.Protocol.Tests`

## Phase 6 — Docs and release readiness
- [x] Update `HIP.Simulator.README.md` with protocol-first operation.
- [x] Update protocol spec cross-references to simulator evidence path.
- [x] Final verification sweep:
  - [x] `dotnet build HIP.sln`
  - [x] CLI sample runs for application + protocol modes
  - [x] benchmark guardrail script unchanged/green
