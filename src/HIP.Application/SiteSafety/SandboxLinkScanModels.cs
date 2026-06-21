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
    DateTimeOffset RequestedAtUtc);

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
    private readonly ConcurrentQueue<SandboxLinkScanRequest> requests = new();

    /// <inheritdoc />
    public Task EnqueueAsync(SandboxLinkScanRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        requests.Enqueue(request);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<SandboxLinkScanRequest>> DequeueBatchAsync(int maxCount, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var batch = new List<SandboxLinkScanRequest>(Math.Max(0, maxCount));
        while (batch.Count < maxCount && requests.TryDequeue(out var request))
        {
            batch.Add(request);
        }

        return Task.FromResult<IReadOnlyCollection<SandboxLinkScanRequest>>(batch);
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
