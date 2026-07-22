using System.Collections.Concurrent;
using HIP.Application.Reporting;
using Microsoft.Extensions.Logging;

namespace HIP.Application.SiteSafety;

/// <summary>
/// Controls HIP's sandbox link scan queue behavior.
/// </summary>
/// <param name="Enabled">Whether risky scan results should enqueue sandbox work.</param>
/// <param name="PersistRawTargetUrls">Whether queued work may keep raw target URLs. Keep false unless a hardened sandbox worker needs it.</param>
/// <param name="MaxQueuedLinksPerScan">Maximum number of observed links to queue from one page scan.</param>
/// <param name="QueueSuspiciousResults">Whether suspicious, high-risk, and dangerous page results should be queued.</param>
public sealed record SandboxLinkScanOptions(
    bool Enabled = true,
    bool PersistRawTargetUrls = false,
    int MaxQueuedLinksPerScan = 5,
    bool QueueSuspiciousResults = true);

/// <summary>
/// Represents the reason HIP asked a sandbox worker to inspect a link.
/// </summary>
public enum SandboxLinkScanReason
{
    /// <summary>
    /// The page scan returned a suspicious or worse status.
    /// </summary>
    RiskyPageStatus,

    /// <summary>
    /// The client observed a download-like link that should not inherit parent-domain trust.
    /// </summary>
    DownloadCandidate,

    /// <summary>
    /// The client observed redirect behavior that may need isolated follow-up.
    /// </summary>
    RedirectCandidate
}

/// <summary>Durable execution state for one sandbox link scan job.</summary>
public enum SandboxLinkScanJobStatus
{
    Pending,
    Processing,
    RetryScheduled,
    Completed,
    DeadLettered,
    Cancelled
}

/// <summary>
/// Privacy-safe request queued for a future hardened link sandbox worker.
/// </summary>
/// <param name="RequestId">Stable request identifier.</param>
/// <param name="Domain">Normalized domain related to the scan.</param>
/// <param name="TargetUrlHash">Keyed hash of the target URL so HIP can dedupe without exposing browsing history.</param>
/// <param name="RawTargetUrl">Optional raw target URL. It is null by default to avoid storing browsing history.</param>
/// <param name="Reason">Why HIP queued this sandbox check.</param>
/// <param name="SourceScanId">Site Safety scan that created this request.</param>
/// <param name="SourceStatus">Status from the source scan.</param>
/// <param name="RequestedAtUtc">UTC time the request was queued.</param>
public sealed record SandboxLinkScanRequest(
    string RequestId,
    string Domain,
    string TargetUrlHash,
    string? RawTargetUrl,
    SandboxLinkScanReason Reason,
    string SourceScanId,
    SiteSafetyScanStatus SourceStatus,
    DateTimeOffset RequestedAtUtc)
{
    public SandboxLinkScanJobStatus Status { get; init; } = SandboxLinkScanJobStatus.Pending;
    public int AttemptCount { get; init; }
    public DateTimeOffset? NextAttemptAtUtc { get; init; }
    public string? LeaseToken { get; init; }
    public string? LeaseOwner { get; init; }
    public DateTimeOffset? LeaseExpiresAtUtc { get; init; }
    public string? LastError { get; init; }
    public DateTimeOffset? CompletedAtUtc { get; init; }
    public long Version { get; init; } = 1;

    public override string ToString() =>
        $"SandboxLinkScanRequest {{ RequestId = {RequestId}, Domain = {Domain}, Status = {Status}, AttemptCount = {AttemptCount} }}";
}

/// <summary>
/// Queue boundary for sandboxed link analysis work.
/// </summary>
public interface ISandboxLinkScanQueue
{
    /// <summary>
    /// Enqueues one privacy-safe sandbox scan request.
    /// </summary>
    /// <param name="request">Request to enqueue.</param>
    /// <param name="cancellationToken">Token used to cancel queue work.</param>
    /// <returns>A task that completes when the request has been accepted.</returns>
    Task EnqueueAsync(SandboxLinkScanRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Dequeues a bounded batch for a future sandbox worker.
    /// </summary>
    /// <param name="maxCount">Maximum number of requests to dequeue.</param>
    /// <param name="cancellationToken">Token used to cancel queue work.</param>
    /// <returns>Dequeued sandbox scan requests.</returns>
    Task<IReadOnlyCollection<SandboxLinkScanRequest>> DequeueBatchAsync(int maxCount, CancellationToken cancellationToken);

    /// <summary>Atomically claims the oldest ready job under a bounded worker lease.</summary>
    Task<SandboxLinkScanRequest?> TryClaimNextAsync(
        string workerId,
        DateTimeOffset nowUtc,
        TimeSpan leaseDuration,
        int maximumAttempts,
        CancellationToken cancellationToken);

    /// <summary>Completes a job only while its matching lease is still current.</summary>
    Task<bool> TryCompleteAsync(string requestId, string leaseToken, DateTimeOffset completedAtUtc, CancellationToken cancellationToken);

    /// <summary>Schedules a bounded retry or moves a leased job to the dead-letter state.</summary>
    Task<bool> TryFailAsync(
        string requestId,
        string leaseToken,
        string safeError,
        DateTimeOffset failedAtUtc,
        DateTimeOffset? nextAttemptAtUtc,
        CancellationToken cancellationToken);

    /// <summary>Cancels pending, retrying, or currently leased work without deleting its audit state.</summary>
    Task<bool> TryCancelAsync(string requestId, DateTimeOffset cancelledAtUtc, CancellationToken cancellationToken);
}

/// <summary>
/// Application service that turns risky Site Safety results into sandbox scan queue requests.
/// </summary>
public interface ISandboxLinkScanService
{
    /// <summary>
    /// Queues sandbox work when a scan result has meaningful link risk.
    /// </summary>
    /// <param name="request">Original Site Safety request. Raw page text and form values are not present here.</param>
    /// <param name="result">Completed Site Safety result.</param>
    /// <param name="cancellationToken">Token used to cancel queue work.</param>
    /// <returns>A task that completes when any required sandbox work has been queued.</returns>
    Task QueueIfNeededAsync(SiteSafetyScanRequest request, SiteSafetyScanResult result, CancellationToken cancellationToken);
}

/// <summary>
/// Local development and test queue for sandbox scan requests.
/// </summary>
public sealed class InMemorySandboxLinkScanQueue : ISandboxLinkScanQueue
{
    private readonly ConcurrentDictionary<string, SandboxLinkScanRequest> requests = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim gate = new(1, 1);

    /// <inheritdoc />
    public Task EnqueueAsync(SandboxLinkScanRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!requests.TryAdd(request.RequestId, request))
        {
            throw new InvalidOperationException("Sandbox link scan request already exists.");
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<SandboxLinkScanRequest>> DequeueBatchAsync(int maxCount, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await gate.WaitAsync(cancellationToken);
        try
        {
            var batch = requests.Values
                .Where(request => request.Status == SandboxLinkScanJobStatus.Pending)
                .OrderBy(request => request.RequestedAtUtc)
                .ThenBy(request => request.RequestId, StringComparer.Ordinal)
                .Take(Math.Max(0, maxCount))
                .ToArray();
            foreach (var request in batch)
            {
                requests.TryRemove(request.RequestId, out _);
            }

            return batch;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<SandboxLinkScanRequest?> TryClaimNextAsync(
        string workerId,
        DateTimeOffset nowUtc,
        TimeSpan leaseDuration,
        int maximumAttempts,
        CancellationToken cancellationToken)
    {
        SandboxLinkScanJobContract.ValidateClaim(workerId, leaseDuration, maximumAttempts);
        await gate.WaitAsync(cancellationToken);
        try
        {
            foreach (var exhausted in requests.Values.Where(job => SandboxLinkScanJobContract.IsReady(job, nowUtc) && job.AttemptCount >= maximumAttempts))
            {
                requests[exhausted.RequestId] = SandboxLinkScanJobContract.DeadLetter(exhausted, nowUtc);
            }

            var candidate = requests.Values
                .Where(job => SandboxLinkScanJobContract.IsReady(job, nowUtc) && job.AttemptCount < maximumAttempts)
                .OrderBy(job => job.NextAttemptAtUtc ?? job.RequestedAtUtc)
                .ThenBy(job => job.RequestId, StringComparer.Ordinal)
                .FirstOrDefault();
            if (candidate is null)
            {
                return null;
            }

            var claimed = SandboxLinkScanJobContract.Claim(candidate, workerId, nowUtc, leaseDuration);
            requests[candidate.RequestId] = claimed;
            return claimed;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <inheritdoc />
    public Task<bool> TryCompleteAsync(string requestId, string leaseToken, DateTimeOffset completedAtUtc, CancellationToken cancellationToken) =>
        TryTransitionAsync(requestId, cancellationToken, current => SandboxLinkScanJobContract.Complete(current, leaseToken, completedAtUtc));

    /// <inheritdoc />
    public Task<bool> TryFailAsync(string requestId, string leaseToken, string safeError, DateTimeOffset failedAtUtc, DateTimeOffset? nextAttemptAtUtc, CancellationToken cancellationToken) =>
        TryTransitionAsync(requestId, cancellationToken, current => SandboxLinkScanJobContract.Fail(current, leaseToken, safeError, failedAtUtc, nextAttemptAtUtc));

    /// <inheritdoc />
    public Task<bool> TryCancelAsync(string requestId, DateTimeOffset cancelledAtUtc, CancellationToken cancellationToken) =>
        TryTransitionAsync(requestId, cancellationToken, current => SandboxLinkScanJobContract.Cancel(current, cancelledAtUtc));

    private async Task<bool> TryTransitionAsync(
        string requestId,
        CancellationToken cancellationToken,
        Func<SandboxLinkScanRequest, SandboxLinkScanRequest?> transition)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!requests.TryGetValue(requestId, out var current) || transition(current) is not { } updated)
            {
                return false;
            }

            requests[requestId] = updated;
            return true;
        }
        finally
        {
            gate.Release();
        }
    }
}

/// <summary>Pure transition rules shared by in-memory and durable sandbox queues.</summary>
public static class SandboxLinkScanJobContract
{
    public static void ValidateClaim(string workerId, TimeSpan leaseDuration, int maximumAttempts)
    {
        if (string.IsNullOrWhiteSpace(workerId) || workerId.Length > 128 || workerId.Any(char.IsControl))
            throw new ArgumentException("Sandbox worker ID must be bounded plain text.", nameof(workerId));
        if (leaseDuration < TimeSpan.FromSeconds(1) || leaseDuration > TimeSpan.FromMinutes(10))
            throw new ArgumentOutOfRangeException(nameof(leaseDuration));
        if (maximumAttempts is < 1 or > 10)
            throw new ArgumentOutOfRangeException(nameof(maximumAttempts));
    }

    public static bool IsReady(SandboxLinkScanRequest job, DateTimeOffset nowUtc) =>
        job.Status == SandboxLinkScanJobStatus.Pending ||
        job.Status == SandboxLinkScanJobStatus.RetryScheduled && job.NextAttemptAtUtc <= nowUtc ||
        job.Status == SandboxLinkScanJobStatus.Processing && job.LeaseExpiresAtUtc <= nowUtc;

    public static SandboxLinkScanRequest Claim(SandboxLinkScanRequest job, string workerId, DateTimeOffset nowUtc, TimeSpan leaseDuration) =>
        job with
        {
            Status = SandboxLinkScanJobStatus.Processing,
            AttemptCount = job.AttemptCount + 1,
            NextAttemptAtUtc = null,
            LeaseToken = $"sandbox-lease:{Guid.NewGuid():N}",
            LeaseOwner = workerId.Trim(),
            LeaseExpiresAtUtc = nowUtc.Add(leaseDuration),
            LastError = null,
            Version = job.Version + 1
        };

    public static SandboxLinkScanRequest? Complete(SandboxLinkScanRequest job, string leaseToken, DateTimeOffset completedAtUtc) =>
        HasCurrentLease(job, leaseToken, completedAtUtc)
            ? ClearLease(job with { Status = SandboxLinkScanJobStatus.Completed, CompletedAtUtc = completedAtUtc, LastError = null, Version = job.Version + 1 })
            : null;

    public static SandboxLinkScanRequest? Fail(SandboxLinkScanRequest job, string leaseToken, string safeError, DateTimeOffset failedAtUtc, DateTimeOffset? nextAttemptAtUtc)
    {
        ValidateSafeError(safeError);
        if (nextAttemptAtUtc is not null && nextAttemptAtUtc <= failedAtUtc)
            throw new ArgumentOutOfRangeException(nameof(nextAttemptAtUtc));
        return HasCurrentLease(job, leaseToken, failedAtUtc)
            ? ClearLease(job with
            {
                Status = nextAttemptAtUtc is null ? SandboxLinkScanJobStatus.DeadLettered : SandboxLinkScanJobStatus.RetryScheduled,
                LastError = safeError.Trim(),
                NextAttemptAtUtc = nextAttemptAtUtc,
                CompletedAtUtc = nextAttemptAtUtc is null ? failedAtUtc : null,
                Version = job.Version + 1
            })
            : null;
    }

    public static SandboxLinkScanRequest? Cancel(SandboxLinkScanRequest job, DateTimeOffset cancelledAtUtc) =>
        job.Status is SandboxLinkScanJobStatus.Pending or SandboxLinkScanJobStatus.RetryScheduled or SandboxLinkScanJobStatus.Processing
            ? ClearLease(job with { Status = SandboxLinkScanJobStatus.Cancelled, CompletedAtUtc = cancelledAtUtc, NextAttemptAtUtc = null, Version = job.Version + 1 })
            : null;

    public static SandboxLinkScanRequest DeadLetter(SandboxLinkScanRequest job, DateTimeOffset nowUtc) =>
        ClearLease(job with
        {
            Status = SandboxLinkScanJobStatus.DeadLettered,
            LastError = "Sandbox job exhausted its execution attempts.",
            NextAttemptAtUtc = null,
            CompletedAtUtc = nowUtc,
            Version = job.Version + 1
        });

    private static bool HasCurrentLease(SandboxLinkScanRequest job, string leaseToken, DateTimeOffset nowUtc) =>
        job.Status == SandboxLinkScanJobStatus.Processing &&
        !string.IsNullOrWhiteSpace(leaseToken) &&
        string.Equals(job.LeaseToken, leaseToken, StringComparison.Ordinal) &&
        job.LeaseExpiresAtUtc > nowUtc;

    private static SandboxLinkScanRequest ClearLease(SandboxLinkScanRequest job) =>
        job with { LeaseToken = null, LeaseOwner = null, LeaseExpiresAtUtc = null };

    private static void ValidateSafeError(string safeError)
    {
        if (string.IsNullOrWhiteSpace(safeError) || safeError.Length > 256 || safeError.Any(char.IsControl))
            throw new ArgumentException("Sandbox job errors must be bounded plain text.", nameof(safeError));
    }
}

/// <summary>
/// Default sandbox link scan service. It queues work but does not browse links on the request path.
/// </summary>
/// <remarks>
/// New code, 2026-06-21 12:09 UTC, HIP Development Team: This is like putting risky links into a locked
/// inspection box. HIP remembers a safe fingerprint and why the link needs review, then a future isolated worker can
/// open the box without slowing down the user's browser scan.
/// </remarks>
public sealed class SandboxLinkScanService(
    ISandboxLinkScanQueue queue,
    IPrivacyHashingService hashingService,
    SandboxLinkScanOptions options,
    ILogger<SandboxLinkScanService> logger) : ISandboxLinkScanService
{
    /// <inheritdoc />
    public async Task QueueIfNeededAsync(SiteSafetyScanRequest request, SiteSafetyScanResult result, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);
        if (!options.Enabled || !ShouldQueue(result))
        {
            return;
        }

        var candidates = BuildCandidates(request, result).Take(Math.Max(0, options.MaxQueuedLinksPerScan)).ToArray();
        foreach (var candidate in candidates)
        {
            if (!IsSafeSandboxTarget(candidate.TargetUrl))
            {
                logger.LogWarning("Skipped sandbox link scan candidate for domain {Domain} because the target is local, private, or malformed.", result.Domain);
                continue;
            }

            await queue.EnqueueAsync(CreateRequest(result, candidate), cancellationToken);
            logger.LogInformation("Queued sandbox link scan candidate for domain {Domain} with reason {Reason}.", result.Domain, candidate.Reason);
        }
    }

    /// <summary>
    /// Determines whether a completed scan is important enough to ask for isolated follow-up.
    /// </summary>
    /// <param name="result">Completed Site Safety result.</param>
    /// <returns>True when sandbox work should be queued.</returns>
    private bool ShouldQueue(SiteSafetyScanResult result)
    {
        if (!options.QueueSuspiciousResults)
        {
            return false;
        }

        return result.Status is SiteSafetyScanStatus.Suspicious or SiteSafetyScanStatus.HighRisk or SiteSafetyScanStatus.Dangerous
               || result.DownloadRiskScore > 0
               || result.RedirectRiskScore > 0;
    }

    /// <summary>
    /// Builds candidate target URLs from privacy-safe observed signals and the sanitized page URL.
    /// </summary>
    /// <param name="request">Original request containing observed link metadata only.</param>
    /// <param name="result">Completed scan result.</param>
    /// <returns>Candidate URLs with reasons.</returns>
    private static IEnumerable<SandboxLinkScanCandidate> BuildCandidates(SiteSafetyScanRequest request, SiteSafetyScanResult result)
    {
        yield return new SandboxLinkScanCandidate(result.Url, SandboxLinkScanReason.RiskyPageStatus);

        foreach (var downloadLink in request.ObservedSignals?.DownloadLinks ?? [])
        {
            yield return new SandboxLinkScanCandidate(downloadLink, SandboxLinkScanReason.DownloadCandidate);
        }

        foreach (var redirectLink in request.ObservedSignals?.RedirectChain ?? [])
        {
            yield return new SandboxLinkScanCandidate(redirectLink, SandboxLinkScanReason.RedirectCandidate);
        }
    }

    /// <summary>
    /// Creates a queued sandbox request without storing the raw URL unless policy explicitly allows it.
    /// </summary>
    /// <param name="result">Completed scan result.</param>
    /// <param name="candidate">Candidate link to inspect later.</param>
    /// <returns>Queued sandbox request.</returns>
    private SandboxLinkScanRequest CreateRequest(SiteSafetyScanResult result, SandboxLinkScanCandidate candidate) =>
        new(
            $"sandbox-link-{Guid.NewGuid():N}",
            result.Domain,
            hashingService.Hash(candidate.TargetUrl),
            options.PersistRawTargetUrls ? candidate.TargetUrl : null,
            candidate.Reason,
            result.ScanId,
            result.Status,
            DateTimeOffset.UtcNow);

    /// <summary>
    /// Blocks local and private network targets so a future sandbox worker does not become an SSRF tool.
    /// </summary>
    /// <param name="targetUrl">Observed target URL.</param>
    /// <returns>True when the target is an HTTP/S public host candidate.</returns>
    private static bool IsSafeSandboxTarget(string targetUrl)
    {
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            return false;
        }

        if (uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !System.Net.IPAddress.TryParse(uri.Host, out var address) || !IsPrivateAddress(address);
    }

    /// <summary>
    /// Detects private or link-local IP addresses that sandbox workers must not fetch.
    /// </summary>
    /// <param name="address">Parsed target IP address.</param>
    /// <returns>True when the IP is private, local, or otherwise not a public Internet target.</returns>
    private static bool IsPrivateAddress(System.Net.IPAddress address)
    {
        if (System.Net.IPAddress.IsLoopback(address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? bytes[0] == 10 ||
              bytes[0] == 127 ||
              bytes[0] == 169 && bytes[1] == 254 ||
              bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
              bytes[0] == 192 && bytes[1] == 168
            : address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || bytes[0] is 0xfc or 0xfd;
    }

    /// <summary>
    /// Internal candidate before privacy policy is applied to the queued request.
    /// </summary>
    /// <param name="TargetUrl">Observed URL candidate.</param>
    /// <param name="Reason">Reason HIP should inspect it later.</param>
    private sealed record SandboxLinkScanCandidate(string TargetUrl, SandboxLinkScanReason Reason);
}
