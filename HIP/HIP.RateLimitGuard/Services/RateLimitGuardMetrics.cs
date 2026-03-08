using System.Collections.Concurrent;
using HIP.RateLimitGuard.Models;

namespace HIP.RateLimitGuard.Services;

public sealed class RateLimitGuardMetrics
{
    private long _localOnlyCount;
    private long _manualOverrideCount;
    private long _circuitOpenMs;
    private long _compressionSamples;
    private double _compressionRatioSum;
    private readonly ConcurrentDictionary<GuardReasonCode, long> _blocked = new();
    private readonly ConcurrentDictionary<string, long> _retryByType = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, long> _depthHistogram = new();
    private readonly ConcurrentDictionary<string, long> _duplicateFingerprints = new(StringComparer.Ordinal);

    public void TrackDecision(GuardRequest request, GuardDecision decision)
    {
        if (decision.Action == GuardAction.LocalOnly) Interlocked.Increment(ref _localOnlyCount);
        if (decision.Action is GuardAction.Reject or GuardAction.LocalOnly or GuardAction.Queue)
        {
            _blocked.AddOrUpdate(decision.ReasonCode, 1, (_, c) => c + 1);
        }

        var ratio = request.PromptSizeBeforeCompression <= 0
            ? 1d
            : (double)request.PromptSizeAfterCompression / request.PromptSizeBeforeCompression;
        Interlocked.Increment(ref _compressionSamples);
        lock (this) _compressionRatioSum += ratio;
        _depthHistogram.AddOrUpdate(request.Depth, 1, (_, c) => c + 1);
    }

    public void TrackCircuitOpen(TimeSpan duration) => Interlocked.Add(ref _circuitOpenMs, (long)duration.TotalMilliseconds);

    public void TrackRetry(string requestType) => _retryByType.AddOrUpdate(requestType, 1, (_, c) => c + 1);

    public void TrackManualOverride() => Interlocked.Increment(ref _manualOverrideCount);

    public void TrackDuplicateFingerprint(string fingerprint) => _duplicateFingerprints.AddOrUpdate(fingerprint, 1, (_, c) => c + 1);

    public RateLimitGuardMetricsSnapshot Snapshot(int currentConcurrency)
    {
        var samples = Interlocked.Read(ref _compressionSamples);
        var avg = samples == 0 ? 1d : _compressionRatioSum / samples;

        return new RateLimitGuardMetricsSnapshot(
            LocalOnlyCount: Interlocked.Read(ref _localOnlyCount),
            BlockedByReasonCode: _blocked.ToDictionary(),
            AverageCompressionRatio: avg,
            ConcurrentCount: currentConcurrency,
            CircuitOpenDuration: TimeSpan.FromMilliseconds(Interlocked.Read(ref _circuitOpenMs)),
            RetryCountByType: _retryByType.ToDictionary(),
            ManualOverrideCount: Interlocked.Read(ref _manualOverrideCount),
            RequestDepthHistogram: _depthHistogram.ToDictionary(),
            TopDuplicateFingerprints: _duplicateFingerprints.OrderByDescending(x => x.Value).Take(10).ToDictionary());
    }
}
