using HIP.Application.Reporting;
using HIP.Application.SiteSafety;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.SiteSafety;

/// <summary>
/// Verifies HIP queues risky links for future sandbox analysis without storing private browsing content.
/// </summary>
[TestFixture]
public sealed class SandboxLinkScanServiceTests
{
    /// <summary>
    /// Risky scan results should create sandbox queue work so a future isolated worker can inspect the link later.
    /// </summary>
    [Test]
    public async Task Risky_scan_result_queues_sandbox_request()
    {
        var queue = new InMemorySandboxLinkScanQueue();
        var service = CreateService(queue);
        var result = CreateResult(SiteSafetyScanStatus.HighRisk, "https://risky.example/download");

        await service.QueueIfNeededAsync(
            new SiteSafetyScanRequest(
                "https://risky.example/download",
                new SiteSafetyObservedSignals(DownloadLinks: ["https://risky.example/setup.exe"])),
            result,
            CancellationToken.None);

        var queued = await queue.DequeueBatchAsync(10, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(queued.Count, Is.EqualTo(2));
            Assert.That(queued.First().Domain, Is.EqualTo("risky.example"));
            Assert.That(queued.First().TargetUrlHash, Does.StartWith("sha256:"));
        });
    }

    /// <summary>
    /// Clean pages should not create sandbox work because the popup is the normal place for low-risk details.
    /// </summary>
    [Test]
    public async Task Clean_scan_result_does_not_queue_sandbox_request()
    {
        var queue = new InMemorySandboxLinkScanQueue();
        var service = CreateService(queue);
        var result = CreateResult(SiteSafetyScanStatus.Clean, "https://safe.example/");

        await service.QueueIfNeededAsync(
            new SiteSafetyScanRequest("https://safe.example/"),
            result,
            CancellationToken.None);

        var queued = await queue.DequeueBatchAsync(10, CancellationToken.None);

        Assert.That(queued.Count, Is.EqualTo(0));
    }

    /// <summary>
    /// Raw URLs are not retained by default because a queue of raw links can become browsing history.
    /// </summary>
    [Test]
    public async Task Queued_request_does_not_store_raw_url_by_default()
    {
        var queue = new InMemorySandboxLinkScanQueue();
        var service = CreateService(queue);
        var result = CreateResult(SiteSafetyScanStatus.Suspicious, "https://example.net/suspicious");

        await service.QueueIfNeededAsync(
            new SiteSafetyScanRequest("https://example.net/suspicious"),
            result,
            CancellationToken.None);

        var queued = await queue.DequeueBatchAsync(10, CancellationToken.None);

        Assert.That(queued.Single().RawTargetUrl, Is.Null);
    }

    /// <summary>
    /// Localhost and private targets are blocked so the future sandbox cannot be abused as an internal network scanner.
    /// </summary>
    [Test]
    public async Task Local_or_private_targets_are_not_queued()
    {
        var queue = new InMemorySandboxLinkScanQueue();
        var service = CreateService(queue);
        var result = CreateResult(SiteSafetyScanStatus.Dangerous, "http://localhost/admin");

        await service.QueueIfNeededAsync(
            new SiteSafetyScanRequest("http://localhost/admin"),
            result,
            CancellationToken.None);

        var queued = await queue.DequeueBatchAsync(10, CancellationToken.None);

        Assert.That(queued.Count, Is.EqualTo(0));
    }

    /// <summary>
    /// Creates the sandbox service with safe local defaults for focused tests.
    /// </summary>
    /// <param name="queue">Queue used to capture sandbox requests.</param>
    /// <returns>Sandbox scan service.</returns>
    private static SandboxLinkScanService CreateService(ISandboxLinkScanQueue queue) =>
        new(
            queue,
            new Sha256PrivacyHashingService(),
            new SandboxLinkScanOptions(),
            NullLogger<SandboxLinkScanService>.Instance);

    /// <summary>
    /// Builds a minimal Site Safety result for sandbox queue tests.
    /// </summary>
    /// <param name="status">Status to test.</param>
    /// <param name="url">Sanitized URL associated with the result.</param>
    /// <returns>Site Safety result.</returns>
    private static SiteSafetyScanResult CreateResult(SiteSafetyScanStatus status, string url)
    {
        var impact = new SiteSafetyScoreImpact(50, 50, 50, 50, []);
        return new SiteSafetyScanResult(
            $"site-safety-{Guid.NewGuid():N}",
            url,
            new Uri(url).Host,
            DateTimeOffset.UtcNow,
            0,
            status is SiteSafetyScanStatus.HighRisk or SiteSafetyScanStatus.Dangerous ? 80 : 0,
            0,
            0,
            status is SiteSafetyScanStatus.HighRisk or SiteSafetyScanStatus.Dangerous ? 65 : 0,
            0,
            0,
            status is SiteSafetyScanStatus.Clean ? 0 : 70,
            status,
            "Test scan summary.",
            ["Test reason."],
            status is SiteSafetyScanStatus.Clean ? [] : ["Test warning."],
            [],
            [],
            "Medium",
            50,
            50,
            50,
            50,
            [],
            impact);
    }
}
