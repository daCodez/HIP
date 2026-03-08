namespace HIP.RateLimitGuard.Models;

public sealed record RateLimitGuardMetricsSnapshot(
    long LocalOnlyCount,
    IReadOnlyDictionary<GuardReasonCode, long> BlockedByReasonCode,
    double AverageCompressionRatio,
    int ConcurrentCount,
    TimeSpan CircuitOpenDuration,
    IReadOnlyDictionary<string, long> RetryCountByType,
    IReadOnlyDictionary<int, long> RequestDepthHistogram,
    long ManualOverrideCount,
    IReadOnlyDictionary<string, long> TopDuplicateFingerprints);
