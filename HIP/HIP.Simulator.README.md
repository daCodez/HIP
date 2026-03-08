# HIP Security Event Simulator (Protocol-first)

This adds a simulator subsystem to the existing HIP solution with shared Core logic used by both CLI and Web.

## Projects

- `HIP.Simulator.Core` - simulator domain + orchestration + evaluation + coverage + suggestions + report writers
- `HIP.Simulator.Cli` - thin CLI runner over Core
- `HIP.Simulator.Tests` - NUnit unit tests
- `HIP.Web` integration - admin simulator page + BFF endpoints (no shell execution)

## Architecture guarantees

- Web does **not** call `Process.Start` or shell out.
- CLI and Web both use the same `ISimulationRunner` from `HIP.Simulator.Core`.
- Action precedence is centralized in `SimulationRunOptions.ActionPrecedence`.
- Simulator is modular and isolated; production APIs do not depend on simulator internals.

## Scenarios

Scenario JSON files are under:

- `HIP.Simulator.Cli/scenarios/<suite>/*.json`

Suites included:

- authentication
- device
- token
- messaging
- reputation
- session
- protocol (envelope verify, replay block, timestamp skew block, key-revoked/key-replaced lifecycle)
- uncovered
- invalid

Schema:

- `HIP.Simulator.Cli/scenarios/scenario.schema.json`

Protocol-mode scenarios can use `protocolSteps` with step types such as:
- `SignEnvelope`, `VerifyEnvelope`, `ReplayAttempt`, `TimestampSkew`
- `IssueReceipt`, `VerifyReceipt`
- `ChallengeCreate`, `ChallengeVerify`
- `KeyRevoked`, `KeyReplaced`

## CLI usage

From `HIP/`:

```bash
# Run all suites (default application mode)
dotnet run --project HIP.Simulator.Cli/HIP.Simulator.Cli.csproj -- run --input HIP.Simulator.Cli/scenarios --report HIP.Simulator.Cli/out

# Override execution mode (plumbing now available)
dotnet run --project HIP.Simulator.Cli/HIP.Simulator.Cli.csproj -- run --mode application --input HIP.Simulator.Cli/scenarios --report HIP.Simulator.Cli/out

# Run one suite
dotnet run --project HIP.Simulator.Cli/HIP.Simulator.Cli.csproj -- run --suite authentication --input HIP.Simulator.Cli/scenarios --report HIP.Simulator.Cli/out

# Run protocol suite directly against HIP.Protocol target
dotnet run --project HIP.Simulator.Cli/HIP.Simulator.Cli.csproj -- run --mode protocol --suite protocol --input HIP.Simulator.Cli/scenarios --report HIP.Simulator.Cli/out

# Run one scenario
dotnet run --project HIP.Simulator.Cli/HIP.Simulator.Cli.csproj -- run --scenario brute-force-lock --input HIP.Simulator.Cli/scenarios --report HIP.Simulator.Cli/out

# Validate scenario definitions
dotnet run --project HIP.Simulator.Cli/HIP.Simulator.Cli.csproj -- validate-scenarios --input HIP.Simulator.Cli/scenarios

# List

dotnet run --project HIP.Simulator.Cli/HIP.Simulator.Cli.csproj -- list-suites --input HIP.Simulator.Cli/scenarios
dotnet run --project HIP.Simulator.Cli/HIP.Simulator.Cli.csproj -- list-scenarios --input HIP.Simulator.Cli/scenarios
```

CLI prints:
- total scenarios
- passed
- failed
- uncovered
- invalid
- suggested policies generated

Reports are written as JSON + HTML + Markdown suggestions under `--report`.

Execution mode notes:
- `application` mode is implemented.
- `protocol` mode is implemented via HIP.Protocol/HIP.Protocol.Security execution target.
- `hybrid` mode remains reserved and currently returns explicit not-implemented feedback.

## Web usage

Open HIP.Web and navigate to `/simulator`.

Capabilities:
- list suites
- list scenarios
- run suite/scenario
- optional execution mode override (`application|protocol|hybrid`) from UI
- push live status + progress stages via SignalR hub (`/hubs/simulator-runs` events: `runStatusChanged`, `runProgress`)
- auto-reattach to active run when page is re-opened
- inspect result details + rule trace
- inspect uncovered suggestions
- download JSON/HTML report

Web endpoints:
- `GET /bff/simulator/suites`
- `GET /bff/simulator/scenarios?suite=`
- `POST /bff/simulator/run`
- `GET /bff/simulator/runs`
- `GET /bff/simulator/runs/{runId}`
- `POST /bff/simulator/runs/{runId}/cancel`
- `POST /bff/simulator/cleanup`
- `GET /bff/simulator/runs/{runId}/report/json`
- `GET /bff/simulator/runs/{runId}/report/html`

## Security controls in this MVP

- Admin gate check in Web endpoint layer (`IsSimulatorAdmin`), preferring authenticated admin role, with current local-loopback fallback for existing HIP.Web deployment mode.
- No user-controlled file paths accepted by Web run endpoint.
- No OS command execution.
- Inputs constrained to suite/scenario values loaded from known scenario root.
- Structured logs for simulator runs.
- Cancellation support for in-flight runs.
- Run history endpoint for last 100 simulator jobs.
- Strict admin-only mode by default; optional local fallback toggle via `HipSimulator:AllowLoopbackAdminFallback=true`.
- Retention cleanup for run folders (default 14 days) configurable via `HipSimulator:RunRetentionDays`.

## Tests

Run:

```bash
dotnet test HIP.Simulator.Tests/HIP.Simulator.Tests.csproj
```

Covered test areas:
- scenario validation + mode compatibility
- precedence resolution
- uncovered event detection
- policy suggestion generation
- coverage calculation
- multi-step brute-force scenario
- impossible travel scenario
- invalid event handling
- protocol execution routing
- protocol replay/timestamp/key-lifecycle outcomes

## Example output reports

Generated examples:
- `HIP.Simulator.Cli/out/simulation-report-20260306-103336.json`
- `HIP.Simulator.Cli/out/simulation-report-20260306-103336.html`
