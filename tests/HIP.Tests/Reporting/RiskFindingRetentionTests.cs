using HIP.Application.Reporting;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;

namespace HIP.Tests.Reporting;

public sealed class RiskFindingRetentionTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 20, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task User_linked_findings_expire_at_thirty_days_while_unlinked_findings_use_ninety_days()
    {
        var repository = new InMemoryRiskFindingReportRepository();
        await repository.AddAsync(Report("linked-expired", Now.AddDays(-30), senderHash: "sha256:sender"), CancellationToken.None);
        await repository.AddAsync(Report("linked-current", Now.AddDays(-29), senderHash: "sha256:sender"), CancellationToken.None);
        await repository.AddAsync(Report("default-expired", Now.AddDays(-90)), CancellationToken.None);
        await repository.AddAsync(Report("default-current", Now.AddDays(-89)), CancellationToken.None);

        var deleted = await repository.DeleteExpiredAsync(Now, 100, CancellationToken.None);
        var remaining = await repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(deleted, Is.EqualTo(2));
            Assert.That(remaining.Select(report => report.ReportId), Is.EquivalentTo(new[] { "linked-current", "default-current" }));
        });
    }

    [Test]
    public async Task Cleanup_is_bounded_per_batch()
    {
        var repository = new InMemoryRiskFindingReportRepository();
        await repository.AddAsync(Report("expired-1", Now.AddDays(-100)), CancellationToken.None);
        await repository.AddAsync(Report("expired-2", Now.AddDays(-100)), CancellationToken.None);

        Assert.That(await repository.DeleteExpiredAsync(Now, 1, CancellationToken.None), Is.EqualTo(1));
        Assert.That(await repository.ListAsync(CancellationToken.None), Has.Count.EqualTo(1));
    }

    internal static RiskFindingReport Report(string id, DateTimeOffset detectedAtUtc, string? senderHash = null, string? consumerScopeHash = null) =>
        new(
            id,
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            "risk.example",
            "sha256:url",
            null,
            senderHash,
            RiskStatus.HighRisk,
            "Privacy-safe risk signal.",
            detectedAtUtc,
            ReporterTrustLevel.Medium,
            new PrivacySafeEvidence("risk-signal", "Bounded risk evidence.", new Dictionary<string, string>()),
            "signature-placeholder",
            consumerScopeHash);
}
