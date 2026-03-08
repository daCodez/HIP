namespace HIP.RateLimitGuard.Models;

public enum GuardAction { AllowNow, Queue, DedupeReuse, LocalOnly, Reject }

public enum GuardReasonCode
{
    None,
    ManualOnly,
    BudgetExceeded,
    CooldownActive,
    CircuitOpen,
    UnsafeLoop,
    PolicyBlocked,
    ConcurrencyExceeded,
    DedupeHit
}

public enum RequestPriority { Low, Normal, High, Critical }

public enum RequestSource { User, Background, Agent, Scheduled }

public enum DegradedMode { Normal, Constrained, Emergency }

public enum RolloutMode
{
    Shadow,
    EnforceDedupeCooldownConcurrency,
    EnforceBudgetsConstrainedEmergency
}

public enum CircuitState { Closed, Open, HalfOpen }

public sealed record GuardDecision(
    GuardAction Action,
    GuardReasonCode ReasonCode,
    TimeSpan? RetryAfter = null,
    string? ReuseKey = null,
    string? Message = null);

public sealed record GuardRequest(
    string AgentId,
    string RequestType,
    RequestPriority Priority,
    bool RequiresApi,
    bool CanFallbackToLocal,
    string? ParentRequestId,
    string ConversationId,
    string SessionId,
    int Depth,
    TimeSpan MaxWaitTolerance,
    RequestSource Source,
    string NormalizedIntentVersion,
    string Fingerprint,
    string IdempotencyKey,
    int PromptSizeBeforeCompression,
    int PromptSizeAfterCompression,
    string? ChainFingerprint = null,
    DateTimeOffset? Timestamp = null)
{
    public DateTimeOffset EffectiveTimestamp => Timestamp ?? DateTimeOffset.UtcNow;
}

public sealed record ManualOverrideRule(
    string RequestType,
    TimeSpan Window,
    int MaxCalls,
    long MaxTokens,
    string Reason,
    bool Enabled = true);

public sealed record CircuitBreakerOptions(
    int FailureThreshold = 3,
    TimeSpan OpenDuration = default,
    TimeSpan BaseBackoff = default,
    TimeSpan MaxBackoff = default,
    double JitterRatio = 0.2)
{
    public TimeSpan OpenDurationOrDefault => OpenDuration == default ? TimeSpan.FromSeconds(30) : OpenDuration;
    public TimeSpan BaseBackoffOrDefault => BaseBackoff == default ? TimeSpan.FromMilliseconds(200) : BaseBackoff;
    public TimeSpan MaxBackoffOrDefault => MaxBackoff == default ? TimeSpan.FromSeconds(15) : MaxBackoff;
}

public sealed class RateLimitGuardOptions
{
    public RolloutMode RolloutMode { get; init; } = RolloutMode.Shadow;
    public DegradedMode? ForcedMode { get; init; }
    public int MaxDepth { get; init; } = 8;
    public int MaxChainRepeat { get; init; } = 3;
    public int GlobalConcurrentLimit { get; init; } = 16;
    public int PerAgentConcurrentLimit { get; init; } = 4;
    public Dictionary<string, int> PerTypeConcurrentLimits { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public long PerMinuteTokenBudget { get; init; } = 120_000;
    public TimeSpan PerAgentBudgetWindow { get; init; } = TimeSpan.FromMinutes(5);
    public long PerAgentBudgetLimit { get; init; } = 250_000;
    public Dictionary<string, TimeSpan> PerTypeCooldowns { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public TimeSpan CacheTtl { get; init; } = TimeSpan.FromMinutes(10);
    public TimeSpan CacheStaleTtl { get; init; } = TimeSpan.FromMinutes(30);
    public bool EnableStaleWhileRevalidate { get; init; } = true;
    public HashSet<string> ManualOnlyRequestTypes { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public List<ManualOverrideRule> ManualOverrides { get; init; } = [];
    public CircuitBreakerOptions CircuitBreaker { get; init; } = new();
    public Func<RateLimitGuardMetricsSnapshot, DegradedMode>? ModeSelector { get; init; }
}
