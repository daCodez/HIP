using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentValidation;
using HIP.Application.Scalability;
using Microsoft.Extensions.Logging;

namespace HIP.Application.SiteSafety;

/// <summary>Durable execution state for one external site-evidence job.</summary>
public enum ExternalSiteEvidenceJobStatus
{
    /// <summary>The job is durable and ready for its first worker claim.</summary>
    Pending,

    /// <summary>A worker owns a bounded execution lease.</summary>
    Processing,

    /// <summary>A transient failure is waiting for its bounded retry time.</summary>
    RetryScheduled,

    /// <summary>Normalized provider evidence was persisted successfully.</summary>
    Succeeded,

    /// <summary>The job reached a non-retryable or maximum-attempt failure.</summary>
    Failed
}

/// <summary>
/// Encrypted durable state for external evidence work. The job intentionally excludes the raw URL,
/// query string, fragment, provider response bodies, credentials, and private page values.
/// </summary>
public sealed record ExternalSiteEvidenceJob(
    string JobId,
    string Domain,
    string UrlHash,
    SiteSafetyObservedSignals ObservedSignals,
    string RequesterKeyDigest,
    string? SettingsScopeKey,
    DateTimeOffset RequestedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    ExternalSiteEvidenceJobStatus Status,
    int AttemptCount,
    DateTimeOffset? NextAttemptAtUtc,
    string? LeaseToken,
    string? LeaseOwner,
    DateTimeOffset? LeaseExpiresAtUtc,
    IReadOnlyCollection<SiteSafetyEvidence> ProviderEvidence,
    string? LastError,
    DateTimeOffset? CompletedAtUtc,
    long Version)
{
    /// <summary>Returns an operational summary without identity, URL, signal, or provider detail.</summary>
    public override string ToString() => $"ExternalSiteEvidenceJob {{ JobId = {JobId}, Domain = {Domain}, Status = {Status}, AttemptCount = {AttemptCount} }}";
}

/// <summary>Durable persistence boundary for atomic enqueue, leasing, retry, and completion.</summary>
public interface IExternalSiteEvidenceJobRepository
{
    /// <summary>Atomically stores a new job and its related outbox notification.</summary>
    Task EnqueueAsync(ExternalSiteEvidenceJob job, HipDurableEvent queuedEvent, CancellationToken cancellationToken);

    /// <summary>Reads one durable job by identifier.</summary>
    Task<ExternalSiteEvidenceJob?> GetAsync(string jobId, CancellationToken cancellationToken);

    /// <summary>Claims the oldest ready or lease-expired job for one worker.</summary>
    Task<ExternalSiteEvidenceJob?> TryClaimNextAsync(
        string workerId,
        DateTimeOffset nowUtc,
        TimeSpan leaseDuration,
        int maximumAttempts,
        CancellationToken cancellationToken);

    /// <summary>Completes a currently leased job when the lease token still matches.</summary>
    Task<bool> TryCompleteAsync(
        string jobId,
        string leaseToken,
        IReadOnlyCollection<SiteSafetyEvidence> providerEvidence,
        DateTimeOffset completedAtUtc,
        CancellationToken cancellationToken);

    /// <summary>Records a safe retry or terminal failure when the lease token still matches.</summary>
    Task<bool> TryFailAsync(
        string jobId,
        string leaseToken,
        string safeError,
        DateTimeOffset failedAtUtc,
        DateTimeOffset? nextAttemptAtUtc,
        CancellationToken cancellationToken);
}

/// <summary>Validates and accepts privacy-safe external provider work without waiting for providers.</summary>
public sealed class ExternalSiteEvidenceJobService(
    IValidator<SiteSafetyScanRequest> validator,
    IExternalSiteEvidenceJobRepository repository,
    TimeProvider? timeProvider = null)
{
    private const int MaximumScopeKeyLength = 128;
    private const int JobIdLength = 45;
    private readonly TimeProvider timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>Queues external evidence work and returns immediately after its durable outbox transaction commits.</summary>
    public async Task<ExternalSiteEvidenceJob> QueueAsync(
        SiteSafetyScanRequest request,
        string requesterScopeKey,
        string? settingsScopeKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await validator.ValidateAndThrowAsync(request, cancellationToken);
        var requesterDigest = DigestScopeKey(requesterScopeKey);
        var retainedSettingsScope = settingsScopeKey is null ? null : ValidateScopeKey(settingsScopeKey, nameof(settingsScopeKey));
        var targetUri = new Uri(request.Url, UriKind.Absolute);
        var domain = targetUri.Host.Trim().TrimEnd('.').ToLowerInvariant();
        var sanitizedUrl = new UriBuilder(targetUri) { Query = string.Empty, Fragment = string.Empty }.Uri.ToString();
        var now = timeProvider.GetUtcNow();
        var jobId = $"provider-job:{Guid.NewGuid():N}";
        var job = new ExternalSiteEvidenceJob(
            jobId,
            domain,
            SiteSafetyEvidenceHashing.HashUrl(sanitizedUrl),
            SiteSafetyObservedSignalSanitizer.Sanitize(request.ObservedSignals),
            requesterDigest,
            retainedSettingsScope,
            now,
            now,
            ExternalSiteEvidenceJobStatus.Pending,
            AttemptCount: 0,
            NextAttemptAtUtc: null,
            LeaseToken: null,
            LeaseOwner: null,
            LeaseExpiresAtUtc: null,
            ProviderEvidence: Array.Empty<SiteSafetyEvidence>(),
            LastError: null,
            CompletedAtUtc: null,
            Version: 1);
        var queuedEvent = new HipDurableEvent(
            $"evt:{Guid.NewGuid():N}",
            "ExternalSiteEvidenceJobQueued",
            "ExternalSiteEvidenceJob",
            jobId,
            now,
            JsonSerializer.Serialize(new { jobId, domain }),
            HipDurableEventPrivacyLevel.PublicSafe);

        await repository.EnqueueAsync(job, queuedEvent, cancellationToken);
        return job;
    }

    /// <summary>Reads a job only when it belongs to the current requester scope.</summary>
    public async Task<ExternalSiteEvidenceJob?> GetForRequesterAsync(
        string jobId,
        string requesterScopeKey,
        CancellationToken cancellationToken)
    {
        if (!IsCanonicalJobId(jobId))
        {
            return null;
        }
        var requesterDigest = DigestScopeKey(requesterScopeKey);
        var job = await repository.GetAsync(jobId, cancellationToken);
        return job is not null && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(job.RequesterKeyDigest),
            Encoding.ASCII.GetBytes(requesterDigest))
            ? job
            : null;
    }

    /// <summary>Creates the stable one-way owner key used by job lookup authorization.</summary>
    public static string DigestScopeKey(string scopeKey)
    {
        var normalized = ValidateScopeKey(scopeKey, nameof(scopeKey)).ToLowerInvariant();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized))).ToLowerInvariant();
    }

    /// <summary>Checks the bounded provider-job identifier format before any persistence lookup.</summary>
    public static bool IsCanonicalJobId(string? jobId)
    {
        const string prefix = "provider-job:";
        if (jobId is not { Length: JobIdLength } ||
            !jobId.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var character in jobId.AsSpan(prefix.Length))
        {
            if (character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    private static string ValidateScopeKey(string scopeKey, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scopeKey, parameterName);
        var normalized = scopeKey.Trim();
        if (normalized.Length > MaximumScopeKeyLength || normalized.Any(char.IsControl))
        {
            throw new ArgumentException("Provider job scope keys must be bounded plain text.", parameterName);
        }

        return normalized;
    }
}

/// <summary>Bounded lease and retry policy for durable external provider jobs.</summary>
public sealed class ExternalSiteEvidenceJobOptions
{
    /// <summary>Gets or sets the maximum provider execution attempts.</summary>
    public int MaximumAttempts { get; set; } = 3;

    /// <summary>Gets or sets the worker lease duration.</summary>
    public TimeSpan LeaseDuration { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Gets or sets the initial transient-failure retry delay.</summary>
    public TimeSpan InitialRetryDelay { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Validates bounded worker options before processing starts.</summary>
    public static bool Validate(ExternalSiteEvidenceJobOptions options) =>
        options.MaximumAttempts is >= 1 and <= 10 &&
        options.LeaseDuration >= TimeSpan.FromSeconds(5) &&
        options.LeaseDuration <= TimeSpan.FromMinutes(10) &&
        options.InitialRetryDelay >= TimeSpan.FromSeconds(1) &&
        options.InitialRetryDelay <= TimeSpan.FromMinutes(15);
}

/// <summary>Claims and executes one durable external provider job at a time.</summary>
public sealed class ExternalSiteEvidenceJobProcessor(
    IExternalSiteEvidenceJobRepository repository,
    IExternalSiteEvidenceWorkCollector collector,
    IExternalSiteEvidenceSettingsStore settingsStore,
    ExternalSiteEvidenceOptions defaultOptions,
    ExternalSiteEvidenceJobOptions options,
    Microsoft.Extensions.Logging.ILogger<ExternalSiteEvidenceJobProcessor> logger,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>Claims and processes the next ready job, returning false when no work is ready.</summary>
    public async Task<bool> ProcessNextAsync(string workerId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerId);
        if (workerId.Length > 128 || workerId.Any(char.IsControl))
        {
            throw new ArgumentException("Provider worker identifiers must be bounded plain text.", nameof(workerId));
        }
        if (!ExternalSiteEvidenceJobOptions.Validate(options))
        {
            throw new InvalidOperationException("External provider job options are outside supported bounds.");
        }

        var job = await repository.TryClaimNextAsync(
            workerId,
            timeProvider.GetUtcNow(),
            options.LeaseDuration,
            options.MaximumAttempts,
            cancellationToken);
        if (job is null)
        {
            return false;
        }

        try
        {
            var scopedOptions = job.SettingsScopeKey is null
                ? null
                : await settingsStore.GetAsync(job.SettingsScopeKey, cancellationToken);
            using var _ = defaultOptions.UseScopedOverride(scopedOptions);
            var evidence = await collector.CollectAsync(
                new ExternalSiteEvidenceWorkItem(job.Domain, job.UrlHash, job.ObservedSignals),
                cancellationToken);
            var completed = await repository.TryCompleteAsync(
                job.JobId,
                job.LeaseToken!,
                evidence,
                timeProvider.GetUtcNow(),
                cancellationToken);
            if (!completed)
            {
                logger.LogWarning("External provider job {JobId} lost its lease before completion.", job.JobId);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            var transient = exception is TimeoutException or HttpRequestException or OperationCanceledException;
            var now = timeProvider.GetUtcNow();
            var retryAt = transient && job.AttemptCount < options.MaximumAttempts
                ? now.Add(CalculateRetryDelay(job.AttemptCount))
                : (DateTimeOffset?)null;
            var safeError = transient
                ? "External provider job failed transiently."
                : "External provider job failed safely.";
            logger.LogWarning(exception, "External provider job {JobId} failed on attempt {AttemptCount}.", job.JobId, job.AttemptCount);
            await repository.TryFailAsync(
                job.JobId,
                job.LeaseToken!,
                safeError,
                now,
                retryAt,
                cancellationToken);
        }

        return true;
    }

    private TimeSpan CalculateRetryDelay(int attemptCount)
    {
        var multiplier = 1L << Math.Min(Math.Max(0, attemptCount - 1), 8);
        var ticks = Math.Min(options.InitialRetryDelay.Ticks * multiplier, TimeSpan.FromHours(1).Ticks);
        return TimeSpan.FromTicks(ticks);
    }
}

/// <summary>Thread-safe local repository with the same lease transitions as durable runtime storage.</summary>
public sealed class InMemoryExternalSiteEvidenceJobRepository(IOutboxEventRepository outboxRepository) : IExternalSiteEvidenceJobRepository
{
    private readonly ConcurrentDictionary<string, ExternalSiteEvidenceJob> jobs = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim gate = new(1, 1);

    /// <inheritdoc />
    public async Task EnqueueAsync(ExternalSiteEvidenceJob job, HipDurableEvent queuedEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(job);
        ArgumentNullException.ThrowIfNull(queuedEvent);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (jobs.ContainsKey(job.JobId))
            {
                throw new InvalidOperationException("An external evidence job with this identifier already exists.");
            }

            await outboxRepository.SaveAsync(queuedEvent, cancellationToken);
            if (!jobs.TryAdd(job.JobId, job))
            {
                throw new InvalidOperationException("The external evidence job could not be stored atomically.");
            }
        }
        finally
        {
            gate.Release();
        }
    }

    /// <inheritdoc />
    public Task<ExternalSiteEvidenceJob?> GetAsync(string jobId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ExternalSiteEvidenceJobService.IsCanonicalJobId(jobId))
        {
            return Task.FromResult<ExternalSiteEvidenceJob?>(null);
        }

        jobs.TryGetValue(jobId, out var job);
        return Task.FromResult(job);
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

        await gate.WaitAsync(cancellationToken);
        try
        {
            var ready = jobs.Values
                .Where(job => IsReady(job, nowUtc))
                .OrderBy(job => job.NextAttemptAtUtc ?? job.RequestedAtUtc)
                .ThenBy(job => job.JobId, StringComparer.Ordinal)
                .ToArray();
            foreach (var exhausted in ready.Where(job => job.AttemptCount >= maximumAttempts))
            {
                jobs[exhausted.JobId] = MarkAttemptsExhausted(exhausted, nowUtc);
            }

            var candidate = ready.FirstOrDefault(job => job.AttemptCount < maximumAttempts);
            if (candidate is null)
            {
                return null;
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
            jobs[candidate.JobId] = claimed;
            return claimed;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<bool> TryCompleteAsync(
        string jobId,
        string leaseToken,
        IReadOnlyCollection<SiteSafetyEvidence> providerEvidence,
        DateTimeOffset completedAtUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(providerEvidence);
        if (providerEvidence.Count > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(providerEvidence));
        }
        return await TryFinishAsync(jobId, leaseToken, completedAtUtc, job => job with
        {
            Status = ExternalSiteEvidenceJobStatus.Succeeded,
            ProviderEvidence = Array.AsReadOnly(providerEvidence.ToArray()),
            LastError = null,
            CompletedAtUtc = completedAtUtc
        }, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> TryFailAsync(
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

        return await TryFinishAsync(jobId, leaseToken, failedAtUtc, job => job with
        {
            Status = nextAttemptAtUtc is null ? ExternalSiteEvidenceJobStatus.Failed : ExternalSiteEvidenceJobStatus.RetryScheduled,
            LastError = safeError.Trim(),
            NextAttemptAtUtc = nextAttemptAtUtc,
            CompletedAtUtc = nextAttemptAtUtc is null ? failedAtUtc : null
        }, cancellationToken);
    }

    private async Task<bool> TryFinishAsync(
        string jobId,
        string leaseToken,
        DateTimeOffset updatedAtUtc,
        Func<ExternalSiteEvidenceJob, ExternalSiteEvidenceJob> transition,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);
        ArgumentException.ThrowIfNullOrWhiteSpace(leaseToken);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!jobs.TryGetValue(jobId, out var current) ||
                current.Status is not ExternalSiteEvidenceJobStatus.Processing ||
                !string.Equals(current.LeaseToken, leaseToken, StringComparison.Ordinal) ||
                current.LeaseExpiresAtUtc <= updatedAtUtc)
            {
                return false;
            }

            jobs[jobId] = transition(current) with
            {
                LeaseToken = null,
                LeaseOwner = null,
                LeaseExpiresAtUtc = null,
                UpdatedAtUtc = updatedAtUtc,
                Version = current.Version + 1
            };
            return true;
        }
        finally
        {
            gate.Release();
        }
    }

    private static bool IsReady(ExternalSiteEvidenceJob job, DateTimeOffset nowUtc) =>
        job.Status is ExternalSiteEvidenceJobStatus.Pending ||
        job.Status is ExternalSiteEvidenceJobStatus.RetryScheduled && job.NextAttemptAtUtc <= nowUtc ||
        job.Status is ExternalSiteEvidenceJobStatus.Processing && job.LeaseExpiresAtUtc <= nowUtc;

    private static ExternalSiteEvidenceJob MarkAttemptsExhausted(ExternalSiteEvidenceJob job, DateTimeOffset nowUtc) =>
        job with
        {
            Status = ExternalSiteEvidenceJobStatus.Failed,
            LastError = "External provider job exhausted its execution attempts.",
            NextAttemptAtUtc = null,
            LeaseToken = null,
            LeaseOwner = null,
            LeaseExpiresAtUtc = null,
            UpdatedAtUtc = nowUtc,
            CompletedAtUtc = nowUtc,
            Version = job.Version + 1
        };
}
