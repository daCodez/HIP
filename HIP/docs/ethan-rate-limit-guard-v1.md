# Ethan Router RateLimitGuard v1 Design Note

Placement: `HIP/HIP.RateLimitGuard` (+ `HIP/HIP.RateLimitGuard.Tests`).

Rationale: there is no existing C# Ethan router module in HIP; this project is a shared orchestration guard package with clean contracts and zero dependency on API endpoint middleware rate limiting.

## Control flow

1. Router builds `GuardRequest`
2. `EvaluateAsync` applies checks in order:
   - hard manual-only gate
   - loop safety (depth + chain repeat)
   - cache/in-flight dedupe
   - circuit open
   - cooldown
   - concurrency
   - degraded-mode policy
   - budget
3. Guard returns `GuardDecision`.
4. Router executes action.
5. Router calls `CompleteAsync` to update cooldown/cache/circuit and release in-flight state.

## Rollout behavior

- `Shadow`: only hard manual-only rule blocks; all other violations are observed and converted to `AllowNow`.
- `EnforceDedupeCooldownConcurrency`: dedupe/cooldown/concurrency enforced; budget enforced in observe mode.
- `EnforceBudgetsConstrainedEmergency`: full enforcement.

## Current known v1 limits

- In-memory concurrency key cleanup expects `CompleteAsync` always called.
- File-backed stores are simple JSON snapshots (single-writer lock), suitable for single-instance or low write throughput.
