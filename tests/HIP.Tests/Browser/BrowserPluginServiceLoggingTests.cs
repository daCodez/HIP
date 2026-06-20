using HIP.Application.Browser;
using HIP.Application.PublicLookup;
using HIP.Domain.Risk;
using HIP.Tests.Support;
using Microsoft.Extensions.Logging;

namespace HIP.Tests.Browser;

/// <summary>
/// Verifies browser plugin service logs are useful for local debugging without leaking raw page details.
/// </summary>
[TestFixture]
public sealed class BrowserPluginServiceLoggingTests
{
    /// <summary>
    /// Scores a site and verifies the service logs domain, status, and score without logging the raw URL query.
    /// </summary>
    [Test]
    public async Task ScoreSiteAsync_logs_completion_without_raw_url_query()
    {
        var logger = new CapturingLogger<BrowserPluginService>();
        var service = new BrowserPluginService(new StubLookupService(RiskStatus.LimitedTrustData, 55), logger);

        await service.ScoreSiteAsync(new BrowserScoreSiteRequest("https://example.com/path?token=private-value", "example.com"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(logger.Entries.Any(entry =>
                entry.LogLevel == LogLevel.Information &&
                entry.Message.Contains("site score completed", StringComparison.OrdinalIgnoreCase) &&
                entry.Message.Contains("example.com", StringComparison.OrdinalIgnoreCase)), Is.True);
            Assert.That(logger.Messages.Any(message => message.Contains("token=private-value", StringComparison.OrdinalIgnoreCase)), Is.False);
        });
    }

    /// <summary>
    /// Invalid page URLs are rejected and logged without echoing the invalid input value.
    /// </summary>
    [Test]
    public void ScanLinksAsync_logs_invalid_page_url_rejection()
    {
        var logger = new CapturingLogger<BrowserPluginService>();
        var service = new BrowserPluginService(new StubLookupService(RiskStatus.Unknown, 45), logger);

        Assert.ThrowsAsync<ArgumentException>(() => service.ScanLinksAsync(
            new BrowserScanLinksRequest("not-a-url-with-token=secret", ["https://example.com"]),
            CancellationToken.None));

        Assert.Multiple(() =>
        {
            Assert.That(logger.Entries.Any(entry =>
                entry.LogLevel == LogLevel.Warning &&
                entry.Message.Contains("invalid page URL", StringComparison.OrdinalIgnoreCase)), Is.True);
            Assert.That(logger.Messages.Any(message => message.Contains("token=secret", StringComparison.OrdinalIgnoreCase)), Is.False);
        });
    }

    /// <summary>
    /// Link scans log useful count summaries without logging the individual target URL query strings.
    /// </summary>
    [Test]
    public async Task ScanLinksAsync_logs_counts_without_raw_link_urls()
    {
        var logger = new CapturingLogger<BrowserPluginService>();
        var service = new BrowserPluginService(new StubLookupService(RiskStatus.HighRisk, 22), logger);

        await service.ScanLinksAsync(
            new BrowserScanLinksRequest(
                "https://page.example/home",
                ["https://page.example/about", "https://bit.ly/demo?token=private-link", "https://other.example/download?token=secret"]),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(logger.Entries.Any(entry =>
                entry.LogLevel == LogLevel.Information &&
                entry.Message.Contains("link scan completed", StringComparison.OrdinalIgnoreCase) &&
                entry.Message.Contains("page.example", StringComparison.OrdinalIgnoreCase) &&
                entry.Message.Contains("3 submitted links", StringComparison.OrdinalIgnoreCase)), Is.True);
            Assert.That(logger.Messages.Any(message => message.Contains("private-link", StringComparison.OrdinalIgnoreCase)), Is.False);
            Assert.That(logger.Messages.Any(message => message.Contains("token=secret", StringComparison.OrdinalIgnoreCase)), Is.False);
        });
    }

    /// <summary>
    /// Small lookup service used to isolate browser logging behavior from persistence and scoring dependencies.
    /// </summary>
    private sealed class StubLookupService(RiskStatus status, int score) : IPublicDomainLookupService
    {
        /// <inheritdoc />
        public Task<PublicDomainLookupResponse> LookupDomainAsync(string domain, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new PublicDomainLookupResponse(
                domain,
                score,
                score,
                status,
                status.ToString(),
                "NotConfigured",
                ["Stub lookup risk summary."],
                ["Stub lookup reason."],
                ["Stub lookup explanation."],
                status is RiskStatus.HighRisk or RiskStatus.Dangerous ? "RouteToSafetyPage" : "ShowCaution",
                DateTimeOffset.UtcNow,
                "NotConfigured",
                "None",
                null,
                "Unknown",
                "NotConfigured",
                null,
                false,
                $"/lookup/domain/{Uri.EscapeDataString(domain)}",
                score,
                score,
                100 - score,
                "Stub lookup result for logging tests.",
                [],
                0,
                0,
                0,
                0,
                "Test",
                "Stub lookup message."));
        }
    }
}
