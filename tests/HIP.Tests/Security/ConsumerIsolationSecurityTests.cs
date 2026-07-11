using System.Net.Http.Json;
using HIP.Application.Consumer;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using FindingReporterTrustLevel = HIP.Domain.SelfHealing.ReporterTrustLevel;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies authenticated consumers cannot read another consumer's reports or appeals.
/// </summary>
public sealed class ConsumerIsolationSecurityTests
{
    [Test]
    public async Task Consumer_history_is_scoped_to_the_authenticated_consumer()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var consumerA = ConsumerClient(factory, "consumer-a");
        using var consumerB = ConsumerClient(factory, "consumer-b");

        var submitted = await consumerA.PostAsJsonAsync("/api/v1/public/risk-findings", Finding("owned-by-a.example"));
        submitted.EnsureSuccessStatusCode();

        var aReports = await consumerA.GetFromJsonAsync<IReadOnlyCollection<ConsumerReportHistoryItem>>("/api/v1/consumer/reports");
        var bReports = await consumerB.GetFromJsonAsync<IReadOnlyCollection<ConsumerReportHistoryItem>>("/api/v1/consumer/reports");

        Assert.Multiple(() =>
        {
            Assert.That(aReports!.Select(report => report.Domain), Does.Contain("owned-by-a.example"));
            Assert.That(bReports!.Select(report => report.Domain), Does.Not.Contain("owned-by-a.example"));
        });
    }

    [Test]
    public async Task Consumer_appeals_are_scoped_to_the_authenticated_consumer()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var consumerA = ConsumerClient(factory, "appeal-owner-a");
        using var consumerB = ConsumerClient(factory, "appeal-owner-b");

        var submitted = await consumerA.PostAsJsonAsync("/api/v1/consumer/appeals", new ConsumerAppealSubmissionRequest(
            TargetType.Domain,
            "private-appeal-target.example",
            "Privacy-safe appeal reason.",
            new Dictionary<string, string>()));
        submitted.EnsureSuccessStatusCode();

        var aAppeals = await consumerA.GetFromJsonAsync<IReadOnlyCollection<ConsumerAppealItem>>("/api/v1/consumer/appeals");
        var bAppeals = await consumerB.GetFromJsonAsync<IReadOnlyCollection<ConsumerAppealItem>>("/api/v1/consumer/appeals");

        Assert.Multiple(() =>
        {
            Assert.That(aAppeals!.Select(appeal => appeal.TargetId), Does.Contain("private-appeal-target.example"));
            Assert.That(bAppeals!.Select(appeal => appeal.TargetId), Does.Not.Contain("private-appeal-target.example"));
        });
    }

    private static HttpClient ConsumerClient(HipWebApplicationFactory<Program> factory, string consumerId)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Consumer-Id", consumerId);
        return client;
    }

    private static RiskFindingReport Finding(string domain) =>
        new(
            "",
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Domain,
            domain,
            "privacy-safe-url-hash",
            null,
            null,
            RiskStatus.HighRisk,
            "Privacy-safe test finding.",
            DateTimeOffset.UtcNow,
            FindingReporterTrustLevel.Trusted,
            new PrivacySafeEvidence("security-test", "Privacy-safe evidence.", new Dictionary<string, string>()),
            "signature-placeholder");
}
