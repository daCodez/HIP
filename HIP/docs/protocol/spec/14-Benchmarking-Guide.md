# HIP Protocol v1 — Benchmarking Guide

## Project
- `HIP.Protocol.Benchmarks`

## Benchmarks included
- `MicroProtocolBenchmarks` (canonical serialize, hash, sign/verify, replay/timestamp, trust receipt issue/verify)
- `FlowProtocolBenchmarks` (full envelope/HTTP validation flows, challenge/handshake, receipt flow)
- `ScaleProtocolBenchmarks` (sequential + parallel validation, replay load, bulk receipt issue/verify)
- `AsymmetricProtocolBenchmarks` (ECDSA P-256 + Ed25519 verify)
- `FailurePathProtocolBenchmarks` (invalid signature, replay, expired timestamp, malformed envelope rejection)

## Run
From `HIP/`:

```bash
dotnet run -c Release --project HIP.Protocol.Benchmarks/HIP.Protocol.Benchmarks.csproj
```

## Output
BenchmarkDotNet output includes mean/median/stddev, p95 column, and memory allocations.
For p99, consume the full JSON export and derive percentile from raw sample distribution in CI aggregation.

## Performance intent
- Keep protocol verify paths low-latency and allocation-conscious.
- Compare changes over time; flag regressions in p95/p99 and allocations.

## Notes
- These are reference micro/flow/scale benchmarks for hot-path behavior.
- Includes asymmetric verify benchmarks (ECDSA P-256 + Ed25519).
- `1.0` envelopes/receipts use deterministic JSON canonicalization.
- `1.1-binary` is an experimental versioned binary canonical profile for high-throughput sign/verify paths; use only when both producer and verifier support it.

## Optional CI threshold check
After running benchmarks, you can validate guardrails with:

```bash
python3 scripts/check-hip-benchmarks.py HIP.Protocol.Benchmarks/BenchmarkDotNet.Artifacts/results
```
