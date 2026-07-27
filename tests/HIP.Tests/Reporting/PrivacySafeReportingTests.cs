using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Domain.Reputation;
using HIP.Domain.Reporting;
using HIP.Domain.Risk;

namespace HIP.Tests.Reporting;

public sealed class PrivacySafeReportingTests
{
    [Test]
    public async Task Report_can_be_submitted()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report(), CancellationToken.None);

        Assert.That(response.Accepted, Is.True);
        Assert.That(response.ReportId, Is.Not.Empty);
    }

    [Test]
    public async Task Report_rejects_invalid_report_type()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report() with { ReportType = (ReportType)999 }, CancellationToken.None);

        Assert.That(response.Accepted, Is.False);
        Assert.That(response.Message, Does.Contain("Report Type"));
    }

    [Test]
    public async Task Report_rejects_oversized_content()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report() with { ReasonSummary = new string('x', PrivacySafeReportValidator.MaxReasonLength + 1) }, CancellationToken.None);

        Assert.That(response.Accepted, Is.False);
    }

    [Test]
    public async Task Report_stores_url_hash()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report() with { UrlHash = null, RiskyUrl = "https://risk.example/path?secret=not-stored" }, CancellationToken.None);
        var stored = await service.ListAsync(CancellationToken.None);

        Assert.That(response.UrlHash, Does.StartWith("sha256:"));
        Assert.That(stored.Single().UrlHash, Does.StartWith("sha256:"));
    }

    /// <summary>
    /// Verifies privacy hashes are keyed HMAC values, not plain SHA-256 hashes.
    /// </summary>
    [Test]
    public void Privacy_hashing_uses_secret_key_material()
    {
        var first = new Sha256PrivacyHashingService(new PrivacyHashingOptions("hip-test-key-one", AllowDevelopmentKey: false));
        var second = new Sha256PrivacyHashingService(new PrivacyHashingOptions("hip-test-key-two", AllowDevelopmentKey: false));

        var firstHash = first.Hash("https://risk.example/path");
        var secondHash = second.Hash("https://risk.example/path");

        Assert.Multiple(() =>
        {
            Assert.That(firstHash, Does.StartWith("sha256:"));
            Assert.That(firstHash, Is.Not.EqualTo(secondHash));
        });
    }

    /// <summary>
    /// Verifies production mode refuses the shared development privacy hashing key.
    /// </summary>
    [Test]
    public void Privacy_hashing_rejects_development_key_outside_development()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new Sha256PrivacyHashingService(new PrivacyHashingOptions(AllowDevelopmentKey: false)));

        Assert.That(exception?.Message, Does.Contain("Privacy hashing key"));
    }

    [Test]
    public async Task Report_does_not_store_full_private_chat_logs()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report() with
        {
            ReasonSummary = "Full private chat log: hello"
        }, CancellationToken.None);

        Assert.That(response.Accepted, Is.False);
    }

    [Test]
    public async Task Report_status_defaults_to_submitted()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report() with { Status = ReportStatus.Closed }, CancellationToken.None);
        var stored = await service.ListAsync(CancellationToken.None);

        Assert.That(response.Status, Is.EqualTo(ReportStatus.Submitted));
        Assert.That(stored.Single().Status, Is.EqualTo(ReportStatus.Submitted));
    }

    [Test]
    public async Task Suspicious_sender_report_updates_the_hashed_sender_profile()
    {
        var profiles = new InMemoryReputationProfileRepository();
        var reputation = new ReputationService(new InMemoryReputationEventRepository(), profiles);
        var hashing = new Sha256PrivacyHashingService();
        var service = new PrivacySafeReportService(new PrivacySafeReportValidator(), hashing, reputationService: reputation);

        var response = await service.SubmitAsync(
            Report() with { ReportType = ReportType.SuspiciousSender },
            CancellationToken.None);
        var profile = await profiles.GetAsync(
            ReputationSubjectType.Sender,
            hashing.Hash("sender@example"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(response.Accepted, Is.True);
            Assert.That(profile, Is.Not.Null);
            Assert.That(profile!.TargetId, Does.StartWith("sha256:"));
            Assert.That(profile.TargetId, Does.Not.Contain("sender@example"));
            Assert.That(profile.EventCount, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Non_sender_report_does_not_change_sender_reputation()
    {
        var profiles = new InMemoryReputationProfileRepository();
        var reputation = new ReputationService(new InMemoryReputationEventRepository(), profiles);
        var service = new PrivacySafeReportService(
            new PrivacySafeReportValidator(),
            new Sha256PrivacyHashingService(),
            reputationService: reputation);

        var response = await service.SubmitAsync(Report(), CancellationToken.None);
        var senderProfiles = await profiles.ListAsync(ReputationSubjectType.Sender, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(response.Accepted, Is.True);
            Assert.That(senderProfiles, Is.Empty);
        });
    }

    [Test]
    public async Task Shared_report_store_keeps_reports_visible_across_service_scopes()
    {
        var store = new PrivacySafeReportStore();
        var firstScope = new PrivacySafeReportService(
            new PrivacySafeReportValidator(),
            new Sha256PrivacyHashingService(),
            reportStore: store);
        var secondScope = new PrivacySafeReportService(
            new PrivacySafeReportValidator(),
            new Sha256PrivacyHashingService(),
            reportStore: store);

        await firstScope.SubmitAsync(Report(), CancellationToken.None);
        var stored = await secondScope.ListAsync(CancellationToken.None);

        Assert.That(stored, Has.Count.EqualTo(1));
    }

    [Test]
    public void Retention_policy_maps_normal_risky_findings_to_90_days()
    {
        var policy = new ReportRetentionPolicyService().GetPolicy(ReportRetentionCategory.NormalRiskyFinding);

        Assert.That(policy.RetentionPeriod, Is.EqualTo(TimeSpan.FromDays(90)));
    }

    [Test]
    public void Confirmed_dangerous_pattern_can_be_long_term()
    {
        var policy = new ReportRetentionPolicyService().GetPolicy(ReportRetentionCategory.ConfirmedDangerousPattern);

        Assert.That(policy.RetentionPeriod, Is.Null);
        Assert.That(policy.Reason, Does.Contain("long-term"));
    }

    [Test]
    public async Task Cleanup_uses_shorter_retention_for_user_linked_reports()
    {
        var now = new DateTimeOffset(2026, 7, 21, 20, 0, 0, TimeSpan.Zero);
        var service = Service();
        await service.SubmitAsync(Report() with
        {
            ReportId = "linked-expired",
            ReportedAtUtc = now.AddDays(-30)
        }, CancellationToken.None);
        await service.SubmitAsync(Report() with
        {
            ReportId = "unlinked-current",
            SenderHash = null,
            DeviceHash = null,
            ReportedAtUtc = now.AddDays(-89)
        }, CancellationToken.None);

        var deleted = await service.DeleteExpiredAsync(now, 10, CancellationToken.None);
        var remaining = await service.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(deleted, Is.EqualTo(1));
            Assert.That(remaining.Select(report => report.ReportId), Is.EquivalentTo(new[] { "unlinked-current" }));
        });
    }

    private static PrivacySafeReportService Service() =>
        new(new PrivacySafeReportValidator(), new Sha256PrivacyHashingService());

    public static PrivacySafeReport Report() =>
        new(
            "",
            ReportType.RiskyUrl,
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            "Risk.Example",
            "https://risk.example/path",
            null,
            "sender@example",
            "device-1",
            RiskStatus.HighRisk,
            "Suspicious shortened URL pattern.",
            DateTimeOffset.UtcNow,
            ReportStatus.Submitted,
            new PrivacySafeEvidence("url", "Risky URL domain and URL hash only.", new Dictionary<string, string> { ["targetDomain"] = "risk.example" }),
            "hip-signature-placeholder");
}
