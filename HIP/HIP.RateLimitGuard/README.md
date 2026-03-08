# HIP.RateLimitGuard (v1)

Production-minded request guard intended for orchestration chains:

`Specialized Agent -> Ethan Router -> RateLimitGuard -> API`

## What it provides

- Guard actions: `AllowNow`, `Queue`, `DedupeReuse`, `LocalOnly`, `Reject`
- Decision contract: action + reason + `RetryAfter` + `ReuseKey` + `Message`
- Reason codes include: `ManualOnly`, `BudgetExceeded`, `CooldownActive`, `CircuitOpen`, `UnsafeLoop`, `PolicyBlocked`
- Request contract includes routing, depth/chain safety, and prompt compression telemetry fields.
- Concurrency caps: global / per-agent / per-request-type
- Budget + cooldown controls
- In-flight dedupe + cache reuse + stale-while-revalidate
- Retry helper (exponential backoff + jitter)
- Circuit breaker state handling
- Scoped manual overrides
- Degraded modes: `Normal`, `Constrained`, `Emergency`
- Rollout modes:
  - `Shadow`
  - `EnforceDedupeCooldownConcurrency`
  - `EnforceBudgetsConstrainedEmergency`
- Storage abstractions with in-memory + file-backed v1 implementations:
  - `IInflightStore`
  - `IBudgetStore`
  - `ICooldownStore`
  - `ICacheStore`
- Metrics surface:
  - local-only count
  - blocked-by-reason
  - avg compression ratio
  - concurrent count
  - circuit-open duration
  - retry count by type
  - manual override count
  - depth histogram
  - top duplicate fingerprints

## Ethan Router integration (next step)

1. **Instantiate guard once** in router startup and keep singleton lifetime.
2. **Map router request into `GuardRequest`**:
   - `RequestType` from normalized intent class
   - `Fingerprint` from stable semantic hash (intent + key entities + policy version)
   - `IdempotencyKey` from router request UUID
   - `ParentRequestId`/`ConversationId`/`SessionId`/`Depth` from chain context
   - compression sizes from router pre/post compression
3. **Call `EvaluateAsync` before any API dispatch**.
4. **Branch by action**:
   - `AllowNow` -> send API call
   - `Queue` -> enqueue with `RetryAfter`
   - `DedupeReuse` -> return cached/in-flight result by `ReuseKey`
   - `LocalOnly` -> route to non-API fallback path
   - `Reject` -> fail fast with reason and message
5. **Call `CompleteAsync` after API result** to:
   - release concurrency/in-flight keys
   - update circuit state
   - set cooldown and cache result payload
6. **On transient failures**, use `GetRetryDelay(requestType, attempt)`.
7. **Expose `GetMetricsSnapshot()`** to admin/telemetry endpoints.

## Example options

```csharp
var options = new RateLimitGuardOptions
{
    RolloutMode = RolloutMode.EnforceBudgetsConstrainedEmergency,
    GlobalConcurrentLimit = 20,
    PerAgentConcurrentLimit = 4,
    PerTypeConcurrentLimits = new() { ["chat.answer"] = 8, ["tool.search"] = 3 },
    PerMinuteTokenBudget = 120_000,
    PerAgentBudgetLimit = 250_000,
    PerAgentBudgetWindow = TimeSpan.FromMinutes(5),
    PerTypeCooldowns = new() { ["chat.answer"] = TimeSpan.FromSeconds(2) },
    ManualOnlyRequestTypes = new() { "security.escalation" },
    ManualOverrides =
    [
        new ManualOverrideRule("security.escalation", TimeSpan.FromMinutes(10), maxCalls: 5, maxTokens: 50_000, reason: "incident response")
    ],
    ModeSelector = metrics =>
        metrics.ConcurrentCount > 18 ? DegradedMode.Constrained : DegradedMode.Normal
};
```

## File-backed stores (example)

```csharp
var inflight = new FileBackedInflightStore("/var/lib/ethan-guard/inflight.json");
var budgets = new FileBackedBudgetStore("/var/lib/ethan-guard/budgets.json");
var cooldowns = new FileBackedCooldownStore("/var/lib/ethan-guard/cooldowns.json");
var cache = new FileBackedCacheStore("/var/lib/ethan-guard/cache.json");
```
