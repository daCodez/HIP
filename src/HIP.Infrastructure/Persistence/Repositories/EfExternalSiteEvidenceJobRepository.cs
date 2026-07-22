using HIP.Application.Scalability;
using HIP.Application.SiteSafety;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Encrypted durable external-provider job repository using compare-and-swap leases and an atomic outbox write.
/// </summary>
public sealed class EfExternalSiteEvidenceJobRepository(HipRecordStore store) : IExternalSiteEvidenceJobRepository
{
    private const string JobPartition = "external-site-evidence-job";
    private const string OutboxPartition = "outbox-event";
    private const int MaximumProviderResults = 32;

    /// <inheritdoc />
    public async Task EnqueueAsync(
        ExternalSiteEvidenceJob job,
        HipDurableEvent queuedEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(job);
        ArgumentNullException.ThrowIfNull(queuedEvent);
        if (job.Version != 1 || job.Status is not ExternalSiteEvidenceJobStatus.Pending ||
            !string.Equals(queuedEvent.AggregateId, job.JobId, StringComparison.Ordinal))
        {
            throw new ArgumentException("A new provider job must be pending, version one, and bound to its outbox event.", nameof(job));
        }

        var saved = await store.TrySaveVersionedWithRelatedRecordsAsync(
            JobPartition,
            job.JobId,
            job,
            expectedVersion: 0,
            newVersion: 1,
            [new HipRelatedRecordWrite<HipDurableEvent>(OutboxPartition, queuedEvent.EventId, queuedEvent)],
            cancellationToken);
        if (!saved)
        {
            throw new InvalidOperationException("The external evidence job or its outbox event already exists.");
        }
    }

    /// <inheritdoc />
    public async Task<ExternalSiteEvidenceJob?> GetAsync(string jobId, CancellationToken cancellationToken)
    {
        if (!ExternalSiteEvidenceJobService.IsCanonicalJobId(jobId))
        {
            return null;
        }
        var stored = await store.GetVersionedAsync<ExternalSiteEvidenceJob>(JobPartition, jobId, cancellationToken);
        if (stored is null)
        {
            return null;
        }

        return EnsureVersionMatches(stored.Value.Record, stored.Value.AggregateVersion);
    }

    /// <inheritdoc />
    public async Task<ExternalSiteEvidenceJob?> TryClaimNextAsync(
        string workerId,
        DateTimeOffset nowUtc,
        TimeSpan leaseDuration,
        int maximumAttempts,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerId);
        if (workerId.Length > 128 || workerId.Any(char.IsControl))
        {
            throw new ArgumentException("Provider worker identifiers must be bounded plain text.", nameof(workerId));
        }
        if (leaseDuration < TimeSpan.FromSeconds(5) || leaseDuration > TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(nameof(leaseDuration));
        }
        if (maximumAttempts is < 1 or > 10)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumAttempts));
        }

        var candidates = (await store.ListAsync<ExternalSiteEvidenceJob>(JobPartition, cancellationToken))
            .Where(job => IsReady(job, nowUtc))
            .OrderBy(job => job.NextAttemptAtUtc ?? job.RequestedAtUtc)
            .ThenBy(job => job.JobId, StringComparer.Ordinal)
            .Take(32)
            .ToArray();
        foreach (var candidate in candidates)
        {
            if (candidate.AttemptCount >= maximumAttempts)
            {
                var exhausted = candidate with
                {
                    Status = ExternalSiteEvidenceJobStatus.Failed,
                    LastError = "External provider job exhausted its execution attempts.",
                    NextAttemptAtUtc = null,
                    LeaseToken = null,
                    LeaseOwner = null,
                    LeaseExpiresAtUtc = null,
                    UpdatedAtUtc = nowUtc,
                    CompletedAtUtc = nowUtc,
                    Version = candidate.Version + 1
                };
                await store.TryUpdateVersionedAsync(
                    JobPartition,
                    candidate.JobId,
                    exhausted,
                    candidate.Version,
                    exhausted.Version,
                    cancellationToken);
                continue;
            }

            var claimed = candidate with
            {
                Status = ExternalSiteEvidenceJobStatus.Processing,
                AttemptCount = candidate.AttemptCount + 1,
                LeaseToken = $"lease:{Guid.NewGuid():N}",
                LeaseOwner = workerId.Trim(),
                LeaseExpiresAtUtc = nowUtc.Add(leaseDuration),
                NextAttemptAtUtc = null,
                UpdatedAtUtc = nowUtc,
                Version = candidate.Version + 1
            };
            if (await store.TryUpdateVersionedAsync(
                    JobPartition,
                    candidate.JobId,
                    claimed,
                    candidate.Version,
                    claimed.Version,
                    cancellationToken))
            {
                return claimed;
            }
        }

        return null;
    }

    /// <inheritdoc />
    public Task<bool> TryCompleteAsync(
        string jobId,
        string leaseToken,
        IReadOnlyCollection<SiteSafetyEvidence> providerEvidence,
        DateTimeOffset completedAtUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(providerEvidence);
        if (providerEvidence.Count > MaximumProviderResults)
        {
            throw new ArgumentOutOfRangeException(nameof(providerEvidence));
        }

        var frozenEvidence = Array.AsReadOnly(providerEvidence.ToArray());
        return TryTransitionAsync(jobId, leaseToken, completedAtUtc, job => job with
        {
            Status = ExternalSiteEvidenceJobStatus.Succeeded,
            ProviderEvidence = frozenEvidence,
            LastError = null,
            CompletedAtUtc = completedAtUtc
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<bool> TryFailAsync(
        string jobId,
        string leaseToken,
        string safeError,
        DateTimeOffset failedAtUtc,
        DateTimeOffset? nextAttemptAtUtc,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(safeError);
        if (safeError.Length > SiteSafetyProviderResultContract.MaximumErrorLength || safeError.Any(char.IsControl))
        {
            throw new ArgumentException("Provider job errors must be bounded plain text.", nameof(safeError));
        }
        if (nextAttemptAtUtc is not null && nextAttemptAtUtc <= failedAtUtc)
        {
            throw new ArgumentOutOfRangeException(nameof(nextAttemptAtUtc));
        }

        return TryTransitionAsync(jobId, leaseToken, failedAtUtc, job => job with
        {
            Status = nextAttemptAtUtc is null ? ExternalSiteEvidenceJobStatus.Failed : ExternalSiteEvidenceJobStatus.RetryScheduled,
            LastError = safeError.Trim(),
            NextAttemptAtUtc = nextAttemptAtUtc,
            CompletedAtUtc = nextAttemptAtUtc is null ? failedAtUtc : null
        }, cancellationToken);
    }

    private async Task<bool> TryTransitionAsync(
        string jobId,
        string leaseToken,
        DateTimeOffset updatedAtUtc,
        Func<ExternalSiteEvidenceJob, ExternalSiteEvidenceJob> transition,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);
        ArgumentException.ThrowIfNullOrWhiteSpace(leaseToken);
        var stored = await store.GetVersionedAsync<ExternalSiteEvidenceJob>(JobPartition, jobId, cancellationToken);
        if (stored is null)
        {
            return false;
        }

        var current = EnsureVersionMatches(stored.Value.Record, stored.Value.AggregateVersion);
        if (current.Status is not ExternalSiteEvidenceJobStatus.Processing ||
            !string.Equals(current.LeaseToken, leaseToken, StringComparison.Ordinal) ||
            current.LeaseExpiresAtUtc <= updatedAtUtc)
        {
            return false;
        }

        var updated = transition(current) with
        {
            LeaseToken = null,
            LeaseOwner = null,
            LeaseExpiresAtUtc = null,
            UpdatedAtUtc = updatedAtUtc,
            Version = current.Version + 1
        };
        return await store.TryUpdateVersionedAsync(
            JobPartition,
            jobId,
            updated,
            current.Version,
            updated.Version,
            cancellationToken);
    }

    private static ExternalSiteEvidenceJob EnsureVersionMatches(ExternalSiteEvidenceJob job, long aggregateVersion)
    {
        if (job.Version != aggregateVersion || job.Version < 1 || !Enum.IsDefined(job.Status))
        {
            throw new InvalidOperationException("The durable provider job version or status is inconsistent.");
        }

        return job;
    }

    private static bool IsReady(ExternalSiteEvidenceJob job, DateTimeOffset nowUtc) =>
        job.Status is ExternalSiteEvidenceJobStatus.Pending ||
        job.Status is ExternalSiteEvidenceJobStatus.RetryScheduled && job.NextAttemptAtUtc <= nowUtc ||
        job.Status is ExternalSiteEvidenceJobStatus.Processing && job.LeaseExpiresAtUtc <= nowUtc;
}
