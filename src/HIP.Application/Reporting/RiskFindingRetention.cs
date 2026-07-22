using HIP.Domain.Reporting;

namespace HIP.Application.Reporting;

/// <summary>Bounded retention rules for unreviewed risk-finding ingestion records.</summary>
public static class RiskFindingRetention
{
    public static readonly TimeSpan UserLinkedRetention = TimeSpan.FromDays(30);
    public static readonly TimeSpan DefaultRetention = TimeSpan.FromDays(90);

    public static TimeSpan RetentionFor(RiskFindingReport report) =>
        !string.IsNullOrWhiteSpace(report.SenderHash) || !string.IsNullOrWhiteSpace(report.ConsumerScopeHash)
            ? UserLinkedRetention
            : DefaultRetention;

    public static bool IsExpired(RiskFindingReport report, DateTimeOffset nowUtc) =>
        report.DetectedAtUtc <= nowUtc.Subtract(RetentionFor(report));
}

public interface IRiskFindingRetentionService
{
    Task<int> DeleteExpiredBatchAsync(int maximumDeletes, CancellationToken cancellationToken);
}

public sealed class RiskFindingRetentionService(
    IRiskFindingReportRepository repository,
    TimeProvider? timeProvider = null) : IRiskFindingRetentionService
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public Task<int> DeleteExpiredBatchAsync(int maximumDeletes, CancellationToken cancellationToken) =>
        repository.DeleteExpiredAsync(clock.GetUtcNow(), maximumDeletes, cancellationToken);
}
