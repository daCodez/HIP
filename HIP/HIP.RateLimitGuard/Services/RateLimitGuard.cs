using HIP.RateLimitGuard.Abstractions;
using HIP.RateLimitGuard.Models;

namespace HIP.RateLimitGuard.Services;

public sealed class RateLimitGuard(
    RateLimitGuardOptions options,
    IInflightStore inflightStore,
    IBudgetStore budgetStore,
    ICooldownStore cooldownStore,
    ICacheStore cacheStore,
    RateLimitGuardMetrics? metrics = null)
{
    private readonly RateLimitGuardMetrics _metrics = metrics ?? new RateLimitGuardMetrics();
    private readonly Random _rng = new();
    private CircuitState _circuitState = CircuitState.Closed;
    private DateTimeOffset? _circuitOpenUntil;
    private int _consecutiveFailures;

    public RateLimitGuardMetricsSnapshot GetMetricsSnapshot() => _metrics.Snapshot(CurrentConcurrency);

    private int CurrentConcurrency => inflightStore.CountByPrefixAsync("req:").GetAwaiter().GetResult();

    public async Task<GuardDecision> EvaluateAsync(GuardRequest request, CancellationToken ct = default)
    {
        var now = request.EffectiveTimestamp;

        if (options.ManualOnlyRequestTypes.Contains(request.RequestType))
        {
            var manualAllowed = await TryConsumeManualOverrideAsync(request, now, ct);
            if (!manualAllowed)
            {
                return Track(request, new GuardDecision(GuardAction.Reject, GuardReasonCode.ManualOnly, Message: "Manual-only gate active."));
            }
        }

        if (request.Depth > options.MaxDepth || await IsUnsafeLoopAsync(request, ct))
        {
            return Track(request, BlockOrLocal(request, GuardReasonCode.UnsafeLoop, "Runaway chain detected."));
        }

        var cached = await cacheStore.GetAsync($"cache:{request.Fingerprint}", now, ct);
        if (cached is not null)
        {
            _metrics.TrackDuplicateFingerprint(request.Fingerprint);
            if (cached.FreshUntil >= now || (options.EnableStaleWhileRevalidate && cached.StaleUntil >= now))
            {
                return Track(request, new GuardDecision(GuardAction.DedupeReuse, GuardReasonCode.DedupeHit, ReuseKey: cached.Key,
                    Message: cached.FreshUntil >= now ? "Fresh cache reuse." : "Stale-while-revalidate reuse."));
            }
        }

        var dedupeKey = $"dedupe:{request.Fingerprint}";
        if (await inflightStore.GetAsync(dedupeKey, ct) is not null)
        {
            _metrics.TrackDuplicateFingerprint(request.Fingerprint);
            return Track(request, new GuardDecision(GuardAction.DedupeReuse, GuardReasonCode.DedupeHit, ReuseKey: dedupeKey, Message: "In-flight dedupe hit."));
        }

        if (IsCircuitOpen(now))
        {
            var retryAfter = _circuitOpenUntil - now;
            return Track(request, BlockOrLocal(request, GuardReasonCode.CircuitOpen, "Circuit is open.", retryAfter));
        }

        var mode = ResolveMode();

        if (await IsCooldownActiveAsync(request, now, ct))
        {
            var until = await cooldownStore.GetUntilAsync($"cd:{request.RequestType}", now, ct);
            var decision = BlockOrLocal(request, GuardReasonCode.CooldownActive, "Cooldown active.", until - now);
            return Track(request, ApplyRollout(decision, request));
        }

        var concurrencyDecision = await CheckConcurrencyAsync(request, now, ct);
        if (concurrencyDecision is not null)
        {
            return Track(request, ApplyRollout(concurrencyDecision, request));
        }

        if (mode != DegradedMode.Normal && request.CanFallbackToLocal)
        {
            return Track(request, new GuardDecision(GuardAction.LocalOnly, GuardReasonCode.PolicyBlocked, Message: $"Mode={mode}; local fallback."));
        }

        var budgetDecision = await CheckBudgetAsync(request, now, ct);
        if (budgetDecision is not null)
        {
            return Track(request, ApplyRollout(budgetDecision, request));
        }

        await inflightStore.TryAddAsync(dedupeKey, new InflightEntry(request.IdempotencyKey, now, request.Fingerprint, request.RequestType, request.AgentId), ct);
        await inflightStore.TryAddAsync($"req:{request.IdempotencyKey}", new InflightEntry(request.IdempotencyKey, now, request.Fingerprint, request.RequestType, request.AgentId), ct);
        return Track(request, new GuardDecision(GuardAction.AllowNow, GuardReasonCode.None));
    }

    public async Task CompleteAsync(GuardRequest request, bool success, string? responsePayload = null, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        await inflightStore.RemoveAsync($"dedupe:{request.Fingerprint}", ct);
        await inflightStore.RemoveAsync($"req:{request.IdempotencyKey}", ct);
        await inflightStore.RemoveAsync($"req-agent:{request.AgentId}:{request.IdempotencyKey}", ct);
        await inflightStore.RemoveAsync($"req-type:{request.RequestType}:{request.IdempotencyKey}", ct);

        if (options.PerTypeCooldowns.TryGetValue(request.RequestType, out var cd))
        {
            await cooldownStore.SetUntilAsync($"cd:{request.RequestType}", now + cd, ct);
        }

        if (!string.IsNullOrWhiteSpace(responsePayload))
        {
            var key = $"cache:{request.Fingerprint}";
            await cacheStore.SetAsync(key, new CacheEntry(key, responsePayload, now, now + options.CacheTtl, now + options.CacheStaleTtl), ct);
        }

        if (success)
        {
            _consecutiveFailures = 0;
            if (_circuitState == CircuitState.HalfOpen) _circuitState = CircuitState.Closed;
            return;
        }

        _consecutiveFailures++;
        if (_consecutiveFailures >= options.CircuitBreaker.FailureThreshold)
        {
            _circuitState = CircuitState.Open;
            _circuitOpenUntil = now + options.CircuitBreaker.OpenDurationOrDefault;
            _metrics.TrackCircuitOpen(options.CircuitBreaker.OpenDurationOrDefault);
        }
    }

    public TimeSpan GetRetryDelay(string requestType, int attempt)
    {
        _metrics.TrackRetry(requestType);
        var baseDelay = options.CircuitBreaker.BaseBackoffOrDefault.TotalMilliseconds;
        var max = options.CircuitBreaker.MaxBackoffOrDefault.TotalMilliseconds;
        var exp = Math.Min(max, baseDelay * Math.Pow(2, Math.Max(0, attempt - 1)));
        var jitter = 1 + ((_rng.NextDouble() * 2 - 1) * options.CircuitBreaker.JitterRatio);
        return TimeSpan.FromMilliseconds(Math.Max(25, exp * jitter));
    }

    private async Task<bool> TryConsumeManualOverrideAsync(GuardRequest request, DateTimeOffset now, CancellationToken ct)
    {
        var rule = options.ManualOverrides.FirstOrDefault(x => x.Enabled && x.RequestType.Equals(request.RequestType, StringComparison.OrdinalIgnoreCase));
        if (rule is null) return false;

        var calls = await budgetStore.IncrementAsync($"manual:calls:{request.RequestType}", 1, rule.Window, now, ct);
        var tokens = await budgetStore.IncrementAsync($"manual:tokens:{request.RequestType}", request.PromptSizeAfterCompression, rule.Window, now, ct);
        if (calls.Value > rule.MaxCalls || tokens.Value > rule.MaxTokens)
        {
            return false;
        }

        _metrics.TrackManualOverride();
        return true;
    }

    private async Task<bool> IsUnsafeLoopAsync(GuardRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.ChainFingerprint)) return false;
        var result = await budgetStore.IncrementAsync($"chain:{request.ConversationId}:{request.ChainFingerprint}", 1, TimeSpan.FromMinutes(10), request.EffectiveTimestamp, ct);
        return result.Value > options.MaxChainRepeat;
    }

    private async Task<bool> IsCooldownActiveAsync(GuardRequest request, DateTimeOffset now, CancellationToken ct)
    {
        var until = await cooldownStore.GetUntilAsync($"cd:{request.RequestType}", now, ct);
        return until is not null;
    }

    private async Task<GuardDecision?> CheckConcurrencyAsync(GuardRequest request, DateTimeOffset now, CancellationToken ct)
    {
        var global = await inflightStore.CountByPrefixAsync("req:", ct);
        if (global >= options.GlobalConcurrentLimit)
        {
            return QueueOrBlock(request, GuardReasonCode.ConcurrencyExceeded, now);
        }

        var perAgent = await inflightStore.CountByPrefixAsync($"req-agent:{request.AgentId}:", ct);
        if (perAgent >= options.PerAgentConcurrentLimit)
        {
            return QueueOrBlock(request, GuardReasonCode.ConcurrencyExceeded, now);
        }

        if (options.PerTypeConcurrentLimits.TryGetValue(request.RequestType, out var perType))
        {
            var typeCount = await inflightStore.CountByPrefixAsync($"req-type:{request.RequestType}:", ct);
            if (typeCount >= perType)
            {
                return QueueOrBlock(request, GuardReasonCode.ConcurrencyExceeded, now);
            }
        }

        await inflightStore.TryAddAsync($"req-agent:{request.AgentId}:{request.IdempotencyKey}", new InflightEntry(request.IdempotencyKey, now, request.Fingerprint, request.RequestType, request.AgentId), ct);
        await inflightStore.TryAddAsync($"req-type:{request.RequestType}:{request.IdempotencyKey}", new InflightEntry(request.IdempotencyKey, now, request.Fingerprint, request.RequestType, request.AgentId), ct);
        return null;
    }

    private GuardDecision QueueOrBlock(GuardRequest request, GuardReasonCode reason, DateTimeOffset now)
    {
        if (request.MaxWaitTolerance > TimeSpan.Zero)
        {
            var delay = TimeSpan.FromMilliseconds(Math.Min(2500, Math.Max(200, request.MaxWaitTolerance.TotalMilliseconds / 2)));
            return new GuardDecision(GuardAction.Queue, reason, delay, Message: "Concurrency cap reached; queueing.");
        }

        return BlockOrLocal(request, reason, "Concurrency cap reached.");
    }

    private async Task<GuardDecision?> CheckBudgetAsync(GuardRequest request, DateTimeOffset now, CancellationToken ct)
    {
        var global = await budgetStore.IncrementAsync("budget:global:minute", request.PromptSizeAfterCompression, TimeSpan.FromMinutes(1), now, ct);
        if (global.Value > options.PerMinuteTokenBudget)
        {
            return BlockOrLocal(request, GuardReasonCode.BudgetExceeded, "Per-minute budget exceeded.", TimeSpan.FromSeconds(15));
        }

        var perAgent = await budgetStore.IncrementAsync($"budget:agent:{request.AgentId}", request.PromptSizeAfterCompression, options.PerAgentBudgetWindow, now, ct);
        if (perAgent.Value > options.PerAgentBudgetLimit)
        {
            return BlockOrLocal(request, GuardReasonCode.BudgetExceeded, "Per-agent budget exceeded.", TimeSpan.FromSeconds(20));
        }

        return null;
    }

    private DegradedMode ResolveMode()
    {
        if (options.ForcedMode is not null) return options.ForcedMode.Value;
        var snap = _metrics.Snapshot(CurrentConcurrency);
        if (options.ModeSelector is not null) return options.ModeSelector(snap);

        if (_circuitState == CircuitState.Open) return DegradedMode.Emergency;
        if (snap.ConcurrentCount >= Math.Max(1, options.GlobalConcurrentLimit - 1)) return DegradedMode.Constrained;
        return DegradedMode.Normal;
    }

    private bool IsCircuitOpen(DateTimeOffset now)
    {
        if (_circuitState != CircuitState.Open) return false;
        if (_circuitOpenUntil is null || now < _circuitOpenUntil) return true;
        _circuitState = CircuitState.HalfOpen;
        return false;
    }

    private GuardDecision ApplyRollout(GuardDecision decision, GuardRequest request)
    {
        if (decision.ReasonCode == GuardReasonCode.ManualOnly) return decision;

        return options.RolloutMode switch
        {
            RolloutMode.Shadow => new GuardDecision(GuardAction.AllowNow, GuardReasonCode.None, Message: $"Shadow observed {decision.ReasonCode}"),
            RolloutMode.EnforceDedupeCooldownConcurrency when decision.ReasonCode == GuardReasonCode.BudgetExceeded =>
                new GuardDecision(GuardAction.AllowNow, GuardReasonCode.None, Message: "Budget gate in observe mode."),
            _ => decision
        };
    }

    private GuardDecision BlockOrLocal(GuardRequest request, GuardReasonCode code, string message, TimeSpan? retry = null)
        => request.CanFallbackToLocal
            ? new GuardDecision(GuardAction.LocalOnly, code, retry, Message: message)
            : new GuardDecision(GuardAction.Reject, code, retry, Message: message);

    private GuardDecision Track(GuardRequest request, GuardDecision decision)
    {
        _metrics.TrackDecision(request, decision);
        return decision;
    }
}
