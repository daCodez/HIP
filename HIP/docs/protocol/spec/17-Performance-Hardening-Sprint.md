# HIP Protocol — Performance Hardening Sprint

## Objective
Reduce GC pressure in HIP protocol hot paths while preserving correctness and low-latency behavior.

## Scope (priority order)
1. Canonical serialization allocations
2. Trust receipt verification allocations
3. Envelope sign/verify allocations

## Baseline capture (before optimization)
From `HIP/`:

```bash
dotnet run -c Release --project HIP.Protocol.Benchmarks/HIP.Protocol.Benchmarks.csproj -- --filter "*MicroProtocolBenchmarks*"
dotnet run -c Release --project HIP.Protocol.Benchmarks/HIP.Protocol.Benchmarks.csproj -- --filter "*FlowProtocolBenchmarks*"
dotnet run -c Release --project HIP.Protocol.Benchmarks/HIP.Protocol.Benchmarks.csproj -- --filter "*ScaleProtocolBenchmarks*"
```

Archive artifacts:
- `BenchmarkDotNet.Artifacts/results/*-report-full.json`
- `BenchmarkDotNet.Artifacts/results/*-report-github.md`

## Optimization steps

### Step A — Canonical serialization
Targets:
- Remove avoidable temporary strings
- Reduce intermediate buffers
- Reuse serialization buffers where safe

Primary metric:
- `CanonicalSerializeEnvelope` allocated bytes

Success target:
- 20–40% allocation reduction without latency regression >10%

### Step B — Trust receipt verification
Targets:
- Minimize canonicalization intermediates on verify path
- Avoid duplicate object creation in receipt verification

Primary metric:
- `VerifyTrustReceipt` allocated bytes

Success target:
- 15–30% allocation reduction without latency regression >10%

### Step C — Envelope sign/verify hot path
Targets:
- Remove avoidable per-call allocations around signing and verification
- Keep logic deterministic and auditable

Primary metrics:
- `SignEnvelope` allocated bytes
- `VerifySignature` allocated bytes

Success target:
- 10–25% allocation reduction without latency regression >10%

## Correctness guardrails (run after each step)
```bash
dotnet test HIP.Protocol.Tests/HIP.Protocol.Tests.csproj
dotnet test HIP.Simulator.Tests/HIP.Simulator.Tests.csproj
```

## Final verification sweep
```bash
dotnet run -c Release --project HIP.Protocol.Benchmarks/HIP.Protocol.Benchmarks.csproj -- --filter "*MicroProtocolBenchmarks*"
dotnet run -c Release --project HIP.Protocol.Benchmarks/HIP.Protocol.Benchmarks.csproj -- --filter "*FlowProtocolBenchmarks*"
dotnet run -c Release --project HIP.Protocol.Benchmarks/HIP.Protocol.Benchmarks.csproj -- --filter "*ScaleProtocolBenchmarks*"
dotnet run -c Release --project HIP.Protocol.Benchmarks/HIP.Protocol.Benchmarks.csproj -- --filter "*FailurePathProtocolBenchmarks*"
```

## Sprint pass/fail criteria
PASS when all are true:
- Protocol and simulator test suites are green
- No critical-path latency regression above 10%
- Allocation reductions achieved in at least 2 of 3 priority areas
- Flow and scale benchmark behavior remains stable (no new red flags)

## Reporting template (before/after)
| Benchmark | Mean Before | Mean After | P95 Before | P95 After | Alloc Before | Alloc After | Delta % | Verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| CanonicalSerializeEnvelope |  |  |  |  |  |  |  |  |
| VerifyTrustReceipt |  |  |  |  |  |  |  |  |
| SignEnvelope |  |  |  |  |  |  |  |  |
| VerifySignature |  |  |  |  |  |  |  |  |

## Notes
- Treat VPS benchmark multimodal warnings as noise signals, not automatic failures.
- Prefer consistency and repeatability over one-off “fastest” runs.
- If benchmark environment changes, record it with the result set.
