using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Certificates;

/// <summary>A privacy-safe record of a scheduled monitoring attempt that could not complete.</summary>
public sealed record DomainMonitoringFailureRecord(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    int ExpectedFailureCount,
    DateTimeOffset FailedAtUtc,
    DateTimeOffset NextCheckAtUtc,
    string AuditEventId);

/// <summary>Persistence boundary for bounded recurring monitoring work and retry state.</summary>
public interface IDomainCertificateMonitoringScheduleRepository
{
    Task<IReadOnlyList<DomainMonitoringEnrollmentState>> ListDueAsync(
        DateTimeOffset dueAtUtc,
        int maximum,
        CancellationToken cancellationToken);

    Task<DomainMonitoringWriteStatus> TryRecordFailureAsync(
        DomainMonitoringFailureRecord record,
        CancellationToken cancellationToken);
}

public sealed record DomainMonitoringCycleSummary(
    int Examined,
    int Checked,
    int Deferred,
    int Conflicted);

public interface IDomainCertificateMonitoringCoordinator
{
    Task<DomainMonitoringCycleSummary> RunDueAsync(int maximum, CancellationToken cancellationToken);
}

/// <summary>Runs bounded server-owned checks and schedules privacy-safe retries without retaining page content.</summary>
public sealed class DomainCertificateMonitoringCoordinator(
    IDomainCertificateMonitoringScheduleRepository repository,
    IDomainCertificateMonitoringService monitoringService,
    TimeProvider timeProvider) : IDomainCertificateMonitoringCoordinator
{
    private static readonly TimeSpan MaximumBackoff = TimeSpan.FromHours(24);

    public async Task<DomainMonitoringCycleSummary> RunDueAsync(
        int maximum,
        CancellationToken cancellationToken)
    {
        if (maximum is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(maximum));
        }

        var now = timeProvider.GetUtcNow().ToUniversalTime();
        var due = await repository.ListDueAsync(now, maximum, cancellationToken).ConfigureAwait(false);
        var checkedCount = 0;
        var deferred = 0;
        var conflicted = 0;

        foreach (var state in due)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DomainCertificateMonitoringStartResult result;
            try
            {
                // An active certificate proves the account-contact requirement passed at issuance.
                result = await monitoringService.StartAsync(
                    state.OwnerId,
                    state.Domain,
                    accountContactVerified: true,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                result = new DomainCertificateMonitoringStartResult(
                    DomainCertificateMonitoringStartStatus.Unavailable);
            }

            if (result.LastCheckedAtUtc is not null)
            {
                checkedCount++;
                continue;
            }

            if (result.Status == DomainCertificateMonitoringStartStatus.Conflict)
            {
                conflicted++;
                continue;
            }

            var failureCount = checked(state.MonitoringFailureCount + 1);
            var nextCheck = now.Add(Backoff(failureCount));
            var failure = new DomainMonitoringFailureRecord(
                state.EnrollmentId,
                state.OwnerId,
                state.Domain,
                state.MonitoringFailureCount,
                now,
                nextCheck,
                FailureEventId(state.EnrollmentId, now));
            var write = await repository.TryRecordFailureAsync(failure, cancellationToken).ConfigureAwait(false);
            if (write is DomainMonitoringWriteStatus.Updated or DomainMonitoringWriteStatus.Existing)
            {
                deferred++;
            }
            else
            {
                conflicted++;
            }
        }

        return new DomainMonitoringCycleSummary(due.Count, checkedCount, deferred, conflicted);
    }

    private static TimeSpan Backoff(int failureCount)
    {
        var hours = Math.Pow(2, Math.Clamp(failureCount - 1, 0, 4));
        return TimeSpan.FromHours(Math.Min(hours, MaximumBackoff.TotalHours));
    }

    private static string FailureEventId(string enrollmentId, DateTimeOffset failedAtUtc)
    {
        var material = $"{enrollmentId}\n{failedAtUtc:O}";
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
        return $"certificate-event:monitoring-deferred:{digest[..48]}";
    }
}
